"""Interventional Validator and Formal Necessity/Specificity Metrics Engine.

Implements Section 1.2 (Objective 2), Section 2.2, and Section 6 of the
JANUS-Evidence Master Project Plan (v1.2.0):

1. Necessity (Nec):
   Nec(c) = 1 - Profit(Fork(b), do(c = off)) / Profit_orig
   Acceptance Threshold: Nec(c) >= tau_n = 0.9

2. Specificity (Spec):
   Spec(c) = (1 / k) * sum_{i=1}^k I( Profit(Fork(b), do(ctrl_i = off)) >= (1 - epsilon) * Profit_orig )
   Acceptance Threshold: Spec(c) >= tau_s = 0.8 (with k >= 10, epsilon = 0.05)
"""

from __future__ import annotations

from enum import Enum
from typing import ClassVar, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.agents.exploit_agent import ExploitReplayPlan
from core.analyzer.graph_builder import EvidenceGraph
from core.validator.fork_sandbox import ForkExecutionResult, ForkSandbox
from core.validator.mutator import (
    DEFAULT_CONTROL_COUNT,
    MutationOperator,
    MutationSpec,
    ProgrammaticMutator,
)

TAU_NECESSITY: float = 0.9
TAU_SPECIFICITY: float = 0.8
DEFAULT_CONTROL_K: int = DEFAULT_CONTROL_COUNT
DEFAULT_EPSILON: float = 0.05


class ValidationDecision(str, Enum):
    """Terminal root-cause validation decisions emitted by the InterventionalValidator."""

    ACCEPTED_AS_ROOT_CAUSE = "ACCEPTED_AS_ROOT_CAUSE"
    REJECTED_NON_CAUSAL = "REJECTED_NON_CAUSAL"


def compute_necessity(
    profit_orig: int,
    profit_intervened: int,
    reverted: bool = False,
) -> float:
    """Compute Necessity Nec(c) = 1 - Profit(Fork(b), do(c=off)) / Profit_orig.

    Edge cases:
    - If `profit_orig <= 0`: returns 0.0 safely (no positive baseline profit to explain).
    - If `reverted` is True or `profit_intervened <= 0`: effective intervened profit is 0,
      yielding Nec(c) = 1.0.
    - Result is clamped to [0.0, 1.0].
    """
    if profit_orig <= 0:
        return 0.0

    effective_intervened = 0 if (reverted or profit_intervened <= 0) else profit_intervened
    raw_nec = 1.0 - (float(effective_intervened) / float(profit_orig))
    return max(0.0, min(1.0, raw_nec))


def compute_specificity(
    profit_orig: int,
    control_results: List[ForkExecutionResult],
    epsilon: float = DEFAULT_EPSILON,
) -> float:
    """Compute Specificity Spec(c) over k control interventions do(ctrl_i = off).

    Spec(c) = (1 / k) * sum_{i=1}^k I( Profit(Fork(b), do(ctrl_i=off)) >= (1 - epsilon) * Profit_orig )

    Edge cases:
    - If `profit_orig <= 0` or `control_results` is empty: returns 0.0 safely.
    - Reverted control executions are treated as profit = 0.
    """
    if profit_orig <= 0 or not control_results:
        return 0.0

    threshold = (1.0 - epsilon) * float(profit_orig)
    preserved_count = 0

    for res in control_results:
        effective_profit = 0 if (res.reverted or not res.success or res.profit_wei <= 0) else res.profit_wei
        if float(effective_profit) >= threshold:
            preserved_count += 1

    return float(preserved_count) / float(len(control_results))


class InterventionResult(BaseModel):
    """Quantitative measurements from baseline, causal do(c=off), and k control do(ctrl_i=off) runs."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    causal_candidate_id: str = Field(..., min_length=1, description="Evaluated causal pointer c")
    operator: MutationOperator = Field(
        default=MutationOperator.DISABLE_STATEMENT,
        description="Applied intervention operator",
    )
    profit_orig: int = Field(..., description="Baseline exploit profit (Profit_orig) in wei")
    profit_causal_intervened: int = Field(
        ..., description="Effective profit under do(c=off) in wei"
    )
    control_profits: List[int] = Field(
        default_factory=list,
        description="Effective profits across all k control mutations do(ctrl_i=off)",
    )
    necessity: float = Field(..., ge=0.0, le=1.0, description="Computed Necessity Nec(c)")
    specificity: float = Field(..., ge=0.0, le=1.0, description="Computed Specificity Spec(c)")
    k_controls: int = Field(..., ge=0, description="Number of control mutations evaluated")
    epsilon: float = Field(default=DEFAULT_EPSILON, ge=0.0, le=1.0, description="Tolerance epsilon")


class ValidationVerdict(BaseModel):
    """Final root-cause validation verdict comparing Nec(c) and Spec(c) against (tau_n, tau_s)."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    ACCEPTED_AS_ROOT_CAUSE: ClassVar[str] = ValidationDecision.ACCEPTED_AS_ROOT_CAUSE.value
    REJECTED_NON_CAUSAL: ClassVar[str] = ValidationDecision.REJECTED_NON_CAUSAL.value

    verdict: ValidationDecision = Field(..., description="Terminal validation decision")
    necessity: float = Field(..., ge=0.0, le=1.0, description="Measured Necessity score")
    specificity: float = Field(..., ge=0.0, le=1.0, description="Measured Specificity score")
    tau_n: float = Field(default=TAU_NECESSITY, description="Necessity acceptance threshold (0.9)")
    tau_s: float = Field(default=TAU_SPECIFICITY, description="Specificity acceptance threshold (0.8)")
    is_accepted: bool = Field(..., description="True iff Nec >= tau_n and Spec >= tau_s")
    intervention_result: InterventionResult = Field(
        ..., description="Detailed counterfactual profit and control measurements"
    )
    reason: str = Field(..., min_length=1, description="Human-readable justification for verdict")

    @property
    def status(self) -> str:
        return self.verdict.value

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ValidationDecision):
            return self.verdict == other
        if isinstance(other, str):
            return self.verdict.value == other
        return super().__eq__(other)


class InterventionalValidator:
    """Orchestrates baseline replay, causal intervention do(c=off), and k control interventions."""

    def __init__(
        self,
        tau_n: float = TAU_NECESSITY,
        tau_s: float = TAU_SPECIFICITY,
        k_controls: int = DEFAULT_CONTROL_K,
        epsilon: float = DEFAULT_EPSILON,
        mutator: Optional[ProgrammaticMutator] = None,
    ) -> None:
        if not (0.0 <= tau_n <= 1.0):
            raise ValueError(f"tau_n must be in [0, 1], got {tau_n}.")
        if not (0.0 <= tau_s <= 1.0):
            raise ValueError(f"tau_s must be in [0, 1], got {tau_s}.")
        if k_controls < 1:
            raise ValueError(f"k_controls must be >= 1, got {k_controls}.")
        if not (0.0 <= epsilon <= 1.0):
            raise ValueError(f"epsilon must be in [0, 1], got {epsilon}.")

        self.tau_n: float = tau_n
        self.tau_s: float = tau_s
        self.k_controls: int = k_controls
        self.epsilon: float = epsilon
        self.mutator: ProgrammaticMutator = mutator or ProgrammaticMutator(default_k=k_controls)

    def validate(
        self,
        plan: ExploitReplayPlan,
        causal_candidate_id: str,
        sandbox: ForkSandbox,
        operator: MutationOperator = MutationOperator.DISABLE_STATEMENT,
        evidence_graph: Optional[EvidenceGraph] = None,
        control_mutations: Optional[List[MutationSpec]] = None,
    ) -> ValidationVerdict:
        """Validate whether `causal_candidate_id` is the true root cause of the exploit in `plan`.

        Steps:
          1. Baseline execution (`mutation=None`) to measure `Profit_orig`.
          2. Causal intervention `do(c=off)` to measure `Nec(c)`.
          3. Control interventions `do(ctrl_i=off)` across `k` controls to measure `Spec(c)`.
          4. Accept iff `Nec(c) >= tau_n` (0.9) and `Spec(c) >= tau_s` (0.8).
        """
        # 1. Baseline execution
        baseline_res = sandbox.replay_exploit(plan, mutation=None)
        profit_orig = baseline_res.profit_wei if (baseline_res.success and not baseline_res.reverted) else 0

        if profit_orig <= 0:
            zero_result = InterventionResult(
                causal_candidate_id=causal_candidate_id,
                operator=operator,
                profit_orig=baseline_res.profit_wei,
                profit_causal_intervened=0,
                control_profits=[],
                necessity=0.0,
                specificity=0.0,
                k_controls=0,
                epsilon=self.epsilon,
            )
            return ValidationVerdict(
                verdict=ValidationDecision.REJECTED_NON_CAUSAL,
                necessity=0.0,
                specificity=0.0,
                tau_n=self.tau_n,
                tau_s=self.tau_s,
                is_accepted=False,
                intervention_result=zero_result,
                reason=(
                    f"Baseline exploit replay did not yield positive profit "
                    f"(profit_orig={baseline_res.profit_wei}, reverted={baseline_res.reverted})."
                ),
            )

        # 2. Necessity test: apply do(cause=off)
        causal_mutation = self.mutator.create_causal_mutation(
            target_pointer=causal_candidate_id,
            operator=operator,
            evidence_graph=evidence_graph,
        )
        causal_res = sandbox.replay_exploit(plan, mutation=causal_mutation)
        effective_causal_profit = (
            0 if (causal_res.reverted or not causal_res.success or causal_res.profit_wei <= 0) else causal_res.profit_wei
        )
        nec = compute_necessity(
            profit_orig=profit_orig,
            profit_intervened=effective_causal_profit,
            reverted=causal_res.reverted or not causal_res.success,
        )

        # 3. Specificity test: apply k control mutations do(ctrl_i=off)
        controls = (
            control_mutations
            if control_mutations is not None
            else self.mutator.generate_control_mutations(
                causal_target_pointer=causal_candidate_id,
                k=self.k_controls,
                operator=operator,
                evidence_graph=evidence_graph,
            )
        )
        control_results: List[ForkExecutionResult] = [
            sandbox.replay_exploit(plan, mutation=ctrl_mut) for ctrl_mut in controls
        ]
        control_profits = [
            0 if (r.reverted or not r.success or r.profit_wei <= 0) else r.profit_wei
            for r in control_results
        ]
        spec = compute_specificity(
            profit_orig=profit_orig,
            control_results=control_results,
            epsilon=self.epsilon,
        )

        # 4. Decision against thresholds (tau_n = 0.9, tau_s = 0.8)
        accepted = (nec >= self.tau_n) and (spec >= self.tau_s)
        decision = (
            ValidationDecision.ACCEPTED_AS_ROOT_CAUSE
            if accepted
            else ValidationDecision.REJECTED_NON_CAUSAL
        )

        if accepted:
            reason = (
                f"Candidate '{causal_candidate_id}' verified as root cause: "
                f"Nec={nec:.3f} >= {self.tau_n} and Spec={spec:.3f} >= {self.tau_s} (k={len(controls)})."
            )
        elif nec < self.tau_n:
            reason = (
                f"Candidate '{causal_candidate_id}' rejected (insufficient Necessity): "
                f"Nec={nec:.3f} < {self.tau_n} (Spec={spec:.3f})."
            )
        else:
            reason = (
                f"Candidate '{causal_candidate_id}' rejected (insufficient Specificity): "
                f"Spec={spec:.3f} < {self.tau_s} (Nec={nec:.3f}, k={len(controls)})."
            )

        int_result = InterventionResult(
            causal_candidate_id=causal_candidate_id,
            operator=operator,
            profit_orig=profit_orig,
            profit_causal_intervened=effective_causal_profit,
            control_profits=control_profits,
            necessity=nec,
            specificity=spec,
            k_controls=len(controls),
            epsilon=self.epsilon,
        )

        return ValidationVerdict(
            verdict=decision,
            necessity=nec,
            specificity=spec,
            tau_n=self.tau_n,
            tau_s=self.tau_s,
            is_accepted=accepted,
            intervention_result=int_result,
            reason=reason,
        )

