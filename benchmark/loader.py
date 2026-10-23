"""Benchmark Dataset Harness & Incident Loader for JANUS-Evidence.

Implements Section 3.1 (Dataset Manifest) and Section 2.3 (6-Slot Ground Truth)
of the JANUS-Evidence Master Project Plan (v1.2.0).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.agents.rca_agent import REQUIRED_RCA_SLOTS

_DEFAULT_BENCHMARK_DIR = Path(__file__).resolve().parent / "evidence_bench"
_DEFAULT_MANIFEST_PATH = _DEFAULT_BENCHMARK_DIR / "incidents.json"
_DEFAULT_GROUND_TRUTH_DIR = _DEFAULT_BENCHMARK_DIR / "ground_truth"


class IncidentMetadata(BaseModel):
    """Metadata descriptor for a single benchmark incident in JANUS-EvidenceBench."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    incident_id: str = Field(
        ...,
        min_length=1,
        description="Unique incident identifier (e.g., DEFI-2026-REENTRANCY-01)",
    )
    protocol_name: str = Field(..., min_length=1, description="Target DeFi protocol name")
    chain: str = Field(
        ...,
        min_length=1,
        description="Target EVM network identifier (e.g., mainnet, bsc, arbitrum)",
    )
    fork_block: int = Field(
        ...,
        ge=0,
        description="Historical block number immediately preceding the exploit transaction",
    )
    target_contract: str = Field(
        ...,
        min_length=1,
        description="Primary vulnerable contract address or name",
    )
    exploit_tx_hash: Optional[str] = Field(
        default=None,
        description="Historical exploit transaction hash (0x...)",
    )
    vulnerability_class: str = Field(
        ...,
        min_length=1,
        description="Canonical vulnerability category (e.g., REENTRANCY, ACCESS_CONTROL)",
    )
    post_cutoff: bool = Field(
        default=False,
        description="True if incident occurred after LLM knowledge cutoff (2026 H2 temporal OOD split)",
    )


class GroundTruthAnnotation(BaseModel):
    """Expert-annotated ground truth for causal localization, non-causal controls, and 6-slot RCA."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    incident_id: str = Field(..., min_length=1, description="Matching incident identifier")
    true_causal_factors: List[str] = Field(
        ...,
        min_length=1,
        description="Expert-verified statement/state pointers that strictly caused the exploit",
    )
    plausible_non_causal_factors: List[str] = Field(
        default_factory=list,
        description="Co-existing sub-optimal patterns or non-essential factors (for B3 vs B7 evaluation)",
    )
    expected_6_slots: Dict[str, Any] = Field(
        ...,
        description="Canonical 6-slot ground truth dictionary for exact-match RCA grading",
    )

    @field_validator("expected_6_slots")
    @classmethod
    def validate_expected_six_slots(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        missing_slots = [slot for slot in REQUIRED_RCA_SLOTS if slot not in value]
        if missing_slots:
            raise ValueError(
                f"expected_6_slots is missing required RCA slots: {missing_slots}. "
                f"Must include all 6 slots: {list(REQUIRED_RCA_SLOTS)}."
            )
        return value


class BenchmarkLoader:
    """Loads, filters, and validates incidents and ground-truth annotations for JANUS-EvidenceBench."""

    def __init__(
        self,
        manifest_path: Optional[Union[str, Path]] = None,
        ground_truth_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        self.manifest_path: Path = (
            Path(manifest_path) if manifest_path is not None else _DEFAULT_MANIFEST_PATH
        )
        self.ground_truth_dir: Path = (
            Path(ground_truth_dir)
            if ground_truth_dir is not None
            else _DEFAULT_GROUND_TRUTH_DIR
        )

    def _read_manifest_entries(self) -> List[IncidentMetadata]:
        """Parse and validate all `IncidentMetadata` records from `self.manifest_path`."""
        if not self.manifest_path.exists():
            raise FileNotFoundError(
                f"Benchmark manifest file not found at '{self.manifest_path}'."
            )

        raw_content = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        raw_list = (
            raw_content.get("incidents", [])
            if isinstance(raw_content, dict)
            else raw_content
        )
        if not isinstance(raw_list, list):
            raise ValueError("Manifest JSON must be a list of incidents or contain an 'incidents' list.")

        return [IncidentMetadata.model_validate(item) for item in raw_list]

    def list_incidents(self, split: Optional[str] = None) -> List[IncidentMetadata]:
        """Return benchmark incidents, optionally filtered by temporal split.

        Args:
            split:
              - `None` or `"all"`: return all incidents.
              - `"in_distribution"` or `"historical"`: return incidents with `post_cutoff == False`.
              - `"post_cutoff"`: return incidents with `post_cutoff == True`.
        """
        incidents = self._read_manifest_entries()
        if split is None or split.lower() == "all":
            return incidents

        normalized = split.lower().strip()
        if normalized in {"in_distribution", "historical"}:
            return [inc for inc in incidents if not inc.post_cutoff]
        if normalized == "post_cutoff":
            return [inc for inc in incidents if inc.post_cutoff]

        raise ValueError(
            f"Unknown split '{split}'. Supported splits: None, 'all', 'in_distribution', 'historical', 'post_cutoff'."
        )

    def load_incident(
        self,
        incident_id: str,
    ) -> Tuple[IncidentMetadata, GroundTruthAnnotation]:
        """Load both `IncidentMetadata` and its corresponding `GroundTruthAnnotation` by `incident_id`."""
        incidents = {inc.incident_id: inc for inc in self._read_manifest_entries()}
        if incident_id not in incidents:
            raise KeyError(f"Incident '{incident_id}' not found in manifest '{self.manifest_path}'.")

        metadata = incidents[incident_id]
        gt_path = self.ground_truth_dir / f"{incident_id}.json"
        if not gt_path.exists():
            raise FileNotFoundError(
                f"Ground truth file for incident '{incident_id}' not found at '{gt_path}'."
            )

        raw_gt = json.loads(gt_path.read_text(encoding="utf-8"))
        annotation = GroundTruthAnnotation.model_validate(raw_gt)

        if annotation.incident_id != metadata.incident_id:
            raise ValueError(
                f"Ground truth incident_id mismatch: expected '{metadata.incident_id}', "
                f"got '{annotation.incident_id}'."
            )

        return metadata, annotation

    def validate_manifest(self) -> bool:
        """Validate schema integrity across the manifest and all linked ground truth files.

        Raises `ValueError`, `FileNotFoundError`, or `ValidationError` if any inconsistency is found.
        Returns `True` if all entries and ground-truth annotations are valid.
        """
        entries = self._read_manifest_entries()
        if not entries:
            raise ValueError("Benchmark manifest contains zero incidents.")

        seen_ids = set()
        for meta in entries:
            if meta.incident_id in seen_ids:
                raise ValueError(f"Duplicate incident_id '{meta.incident_id}' in manifest.")
            seen_ids.add(meta.incident_id)
            # Validate ground truth file existence, schema, and ID alignment
            self.load_incident(meta.incident_id)

        return True

