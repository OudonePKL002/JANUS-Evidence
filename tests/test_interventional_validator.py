"""Unit tests for the Interventional Validator Engine in Step 1.6."""

from typing import Optional

import pytest

from core.agents.exploit_agent import ExploitReplayPlan
from core.validator import (
    ForkExecutionResult,
    ForkSandbox,
    InterventionalValidator,
    MutationOperator,
    MutationSpec,
    ProgrammaticMutator,
    ValidationDecision,
    ValidationVerdict,
    compute_necessity,
    compute_specificity,
)


@pytest.fixture
def sample_replay_plan() -> ExploitReplayPlan:
    """Create a baseline historical fork exploit replay plan (Profit_orig = 100 ETH)."""
    return ExploitReplayPlan(
        plan_id="PLAN-VAL-001",
        incident_id="INC-VAL-001",
        fork_block_number=19500000,
        target_contract="0xVulnerablePool",
        attacker_address="0xAttackerEOA",
        tx_hash="0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        calldata="0xdeadbeef",
        expected_profit_wei=100 * 10**18,
        causal_target_pointer="VulnerablePool:withdraw:3",
        evidence_pointers=["VulnerablePool:withdraw:3"],
    )


def test_case_1_true_root_cause_accepted(sample_replay_plan: ExploitReplayPlan) -> None:
    """Case 1: True Root Cause (Nec = 1.0, Spec = 1.0, k = 10) -> ACCEPTED_AS_ROOT_CAUSE."""
    sandbox = ForkSandbox()  # Default hook: baseline=100 ETH, causal=0 ETH, controls=100 ETH
    validator = InterventionalValidator(tau_n=0.9, tau_s=0.8, k_controls=10, epsilon=0.05)

    verdict = validator.validate(
        plan=sample_replay_plan,
        causal_candidate_id="VulnerablePool:withdraw:3",
        sandbox=sandbox,
        operator=MutationOperator.DISABLE_STATEMENT,
    )

    assert verdict == ValidationVerdict.ACCEPTED_AS_ROOT_CAUSE
    assert verdict.verdict == ValidationDecision.ACCEPTED_AS_ROOT_CAUSE
    assert verdict.is_accepted is True
    assert verdict.necessity == pytest.approx(1.0)
    assert verdict.specificity == pytest.approx(1.0)
    assert verdict.intervention_result.k_controls == 10
    assert verdict.intervention_result.profit_orig == 100 * 10**18
    assert verdict.intervention_result.profit_causal_intervened == 0


def test_case_2_plausible_non_causal_factor_rejected(
    sample_replay_plan: ExploitReplayPlan,
) -> None:
    """Case 2: Non-Causal Factor (Nec = 0.0, attack still extracts full profit) -> REJECTED_NON_CAUSAL."""

    def non_causal_replay_hook(
        plan: ExploitReplayPlan,
        mutation: Optional[MutationSpec],
    ) -> ForkExecutionResult:
        # Even when do(cause=off) is applied to this non-essential bug, the exploit still succeeds!
        return ForkExecutionResult(
            success=True,
            profit_wei=plan.expected_profit_wei,
            reverted=False,
        )

    sandbox = ForkSandbox(replay_hook=non_causal_replay_hook)
    validator = InterventionalValidator(tau_n=0.9, tau_s=0.8, k_controls=10)

    verdict = validator.validate(
        plan=sample_replay_plan,
        causal_candidate_id="VulnerablePool:nonEssentialHelper:1",
        sandbox=sandbox,
        operator=MutationOperator.REVERT_STATE_DELTA,
    )

    assert verdict == ValidationVerdict.REJECTED_NON_CAUSAL
    assert verdict.verdict == ValidationDecision.REJECTED_NON_CAUSAL
    assert verdict.is_accepted is False
    assert verdict.necessity == pytest.approx(0.0)
    assert verdict.specificity == pytest.approx(1.0)
    assert "insufficient Necessity" in verdict.reason


def test_case_3_over_broad_mutation_breaks_controls_rejected(
    sample_replay_plan: ExploitReplayPlan,
) -> None:
    """Case 3: Over-broad mutation breaks unrelated flows (Nec = 1.0, Spec = 0.3 < 0.8) -> REJECTED_NON_CAUSAL."""
    ctrl_call_counter = [0]

    def over_broad_replay_hook(
        plan: ExploitReplayPlan,
        mutation: Optional[MutationSpec],
    ) -> ForkExecutionResult:
        if mutation is None:
            return ForkExecutionResult(success=True, profit_wei=plan.expected_profit_wei)
        if not mutation.is_control:
            # Causal intervention stops the attack
            return ForkExecutionResult(success=False, profit_wei=0, reverted=True)

        # 7 out of 10 control mutations also break contract compilation/execution!
        ctrl_call_counter[0] += 1
        if ctrl_call_counter[0] <= 3:
            return ForkExecutionResult(success=True, profit_wei=plan.expected_profit_wei)
        return ForkExecutionResult(
            success=False,
            profit_wei=0,
            reverted=True,
            error_msg="Control mutation broke general contract execution",
        )

    sandbox = ForkSandbox(replay_hook=over_broad_replay_hook)
    validator = InterventionalValidator(tau_n=0.9, tau_s=0.8, k_controls=10)

    verdict = validator.validate(
        plan=sample_replay_plan,
        causal_candidate_id="VulnerablePool:withdraw:0",
        sandbox=sandbox,
        operator=MutationOperator.LOCK_ORACLE,
    )

    assert verdict == ValidationVerdict.REJECTED_NON_CAUSAL
    assert verdict.is_accepted is False
    assert verdict.necessity == pytest.approx(1.0)
    assert verdict.specificity == pytest.approx(0.3)
    assert "insufficient Specificity" in verdict.reason


def test_case_4_zero_and_negative_profit_edge_cases(
    sample_replay_plan: ExploitReplayPlan,
) -> None:
    """Case 4: Zero or negative baseline profit and reverted runs handled safely without crash."""
    # Direct metric function edge cases
    assert compute_necessity(profit_orig=0, profit_intervened=0) == 0.0
    assert compute_necessity(profit_orig=-500, profit_intervened=0) == 0.0
    assert compute_necessity(profit_orig=1000, profit_intervened=500, reverted=True) == 1.0
    assert compute_specificity(profit_orig=0, control_results=[]) == 0.0
    assert compute_specificity(profit_orig=-100, control_results=[]) == 0.0

    # Validator with zero/negative baseline profit
    zero_plan = sample_replay_plan.model_copy(update={"expected_profit_wei": 0})
    sandbox = ForkSandbox()
    validator = InterventionalValidator()

    verdict = validator.validate(
        plan=zero_plan,
        causal_candidate_id="VulnerablePool:withdraw:3",
        sandbox=sandbox,
    )
    assert verdict == ValidationVerdict.REJECTED_NON_CAUSAL
    assert verdict.is_accepted is False
    assert verdict.necessity == 0.0
    assert verdict.specificity == 0.0

    # Mutator operators verification
    mutator = ProgrammaticMutator(default_k=12)
    for op in (
        MutationOperator.DISABLE_STATEMENT,
        MutationOperator.REVERT_STATE_DELTA,
        MutationOperator.LOCK_ORACLE,
    ):
        c_mut = mutator.create_causal_mutation("VulnerablePool:withdraw:3", operator=op)
        assert c_mut.is_control is False
        assert c_mut.operator == op
        ctrls = mutator.generate_control_mutations("VulnerablePool:withdraw:3", operator=op)
        assert len(ctrls) == 12
        assert all(m.is_control is True for m in ctrls)

