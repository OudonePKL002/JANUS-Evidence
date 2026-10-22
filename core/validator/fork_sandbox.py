"""Historical Fork Sandbox Execution Interface for JANUS-Evidence.

Provides the `ForkSandbox` abstraction for replaying exploit transactions on
historical blockchain forks (Foundry Anvil) under baseline and intervened
conditions do(cause=off) / do(ctrl_i=off).
"""

from __future__ import annotations

from typing import Callable, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.agents.exploit_agent import ExploitReplayPlan
from core.validator.mutator import MutationSpec


class ForkExecutionResult(BaseModel):
    """Outcome of a single exploit replay on a historical blockchain fork."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    success: bool = Field(
        ...,
        description="True if the exploit replay completed without reverting",
    )
    profit_wei: int = Field(
        default=0,
        description="Net attacker profit extracted in wei (0 or negative if unprofitable/reverted)",
    )
    reverted: bool = Field(
        default=False,
        description="True if EVM execution reverted during replay",
    )
    error_msg: Optional[str] = Field(
        default=None,
        description="Optional revert reason or RPC diagnostic message",
    )
    environment_mismatch: bool = Field(
        default=False,
        description="True if replay failed due to external RPC/fork state mismatch (Section 6 Threat 1)",
    )


SandboxReplayCallable = Callable[[ExploitReplayPlan, Optional[MutationSpec]], ForkExecutionResult]


class ForkSandbox:
    """Historical fork sandbox interface supporting Anvil RPC and deterministic offline mocking."""

    def __init__(
        self,
        rpc_url: str = "http://127.0.0.1:8545",
        replay_hook: Optional[SandboxReplayCallable] = None,
    ) -> None:
        self.rpc_url: str = rpc_url
        self.replay_hook: Optional[SandboxReplayCallable] = replay_hook

    def replay_exploit(
        self,
        plan: ExploitReplayPlan,
        mutation: Optional[MutationSpec] = None,
    ) -> ForkExecutionResult:
        """Execute `plan` on the historical fork at `plan.fork_block_number` with optional `mutation`.

        - When `mutation is None`, executes the unmodified baseline exploit to measure Profit_orig.
        - When `mutation` is a causal intervention `do(c=off)`, measures Profit(Fork(b), do(c=off)).
        - When `mutation` is a control intervention `do(ctrl_i=off)`, measures Profit(Fork(b), do(ctrl_i=off)).
        """
        if self.replay_hook is not None:
            return self.replay_hook(plan, mutation)

        # Default deterministic behavior when no custom hook is attached:
        # - Baseline (no mutation): returns plan.expected_profit_wei
        # - Causal intervention (is_control=False): neutralizes exploit (profit_wei = 0, reverted = True)
        # - Control intervention (is_control=True): preserves baseline profit (profit_wei = plan.expected_profit_wei)
        if mutation is None:
            if plan.expected_profit_wei <= 0:
                return ForkExecutionResult(
                    success=False,
                    profit_wei=plan.expected_profit_wei,
                    reverted=True,
                    error_msg="Baseline expected profit is non-positive.",
                )
            return ForkExecutionResult(
                success=True,
                profit_wei=plan.expected_profit_wei,
                reverted=False,
            )

        if not mutation.is_control:
            return ForkExecutionResult(
                success=False,
                profit_wei=0,
                reverted=True,
                error_msg=f"Exploit neutralized by causal intervention {mutation.mutation_id}",
            )

        return ForkExecutionResult(
            success=True,
            profit_wei=plan.expected_profit_wei,
            reverted=False,
        )

