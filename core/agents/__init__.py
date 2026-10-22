"""Role-specialized multi-agent pipeline (Auditor -> Localizer -> RCA -> Exploit)."""

from core.agents.auditor_agent import AuditorAgent, VulnerabilityHypothesis
from core.agents.base_agent import AgentOutput, BaseAgent, LLMBackendCallable
from core.agents.exploit_agent import ExploitAgent, ExploitReplayPlan
from core.agents.localization_agent import LocalizationAgent, LocalizedLocation
from core.agents.pipeline import JanusPipeline, PipelineResult
from core.agents.rca_agent import (
    REQUIRED_RCA_SLOTS,
    RCAAgent,
    RCARevisionCallable,
    RCASlotEntry,
    SixSlotCausalChain,
)

__all__ = [
    "AgentOutput",
    "AuditorAgent",
    "BaseAgent",
    "ExploitAgent",
    "ExploitReplayPlan",
    "JanusPipeline",
    "LLMBackendCallable",
    "LocalizationAgent",
    "LocalizedLocation",
    "PipelineResult",
    "RCAAgent",
    "RCARevisionCallable",
    "RCASlotEntry",
    "REQUIRED_RCA_SLOTS",
    "SixSlotCausalChain",
    "VulnerabilityHypothesis",
]
