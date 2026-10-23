"""Unit tests for the Benchmark Dataset Harness & Incident Loader in Step 1.7."""

import json
from pathlib import Path

import pytest

from benchmark.loader import (
    BenchmarkLoader,
    GroundTruthAnnotation,
    IncidentMetadata,
)
from core.agents.rca_agent import REQUIRED_RCA_SLOTS


def test_seed_manifest_validation_and_loading() -> None:
    """Verify that the seed incidents.json and ground truth files pass schema validation."""
    loader = BenchmarkLoader()
    assert loader.validate_manifest() is True

    meta1, gt1 = loader.load_incident("DEFI-2026-REENTRANCY-01")
    assert isinstance(meta1, IncidentMetadata)
    assert isinstance(gt1, GroundTruthAnnotation)
    assert meta1.protocol_name == "OmniYieldVault"
    assert meta1.chain == "mainnet"
    assert meta1.vulnerability_class == "REENTRANCY"
    assert meta1.post_cutoff is False
    assert "OmniYieldVault:withdrawAll:3" in gt1.true_causal_factors
    assert len(gt1.plausible_non_causal_factors) >= 1
    for slot in REQUIRED_RCA_SLOTS:
        assert slot in gt1.expected_6_slots

    meta2, gt2 = loader.load_incident("DEFI-2026-ACCESS-02")
    assert meta2.protocol_name == "HyperBridgeMigrator"
    assert meta2.chain == "arbitrum"
    assert meta2.vulnerability_class == "ACCESS_CONTROL"
    assert meta2.post_cutoff is True
    assert "HyperBridgeMigrator:emergencySweep:1" in gt2.true_causal_factors
    for slot in REQUIRED_RCA_SLOTS:
        assert slot in gt2.expected_6_slots


def test_list_incidents_split_filtering() -> None:
    """Verify filtering between all, in_distribution (historical), and post_cutoff splits."""
    loader = BenchmarkLoader()

    all_incidents = loader.list_incidents()
    assert len(all_incidents) == 2

    in_dist = loader.list_incidents(split="in_distribution")
    assert len(in_dist) == 1
    assert in_dist[0].incident_id == "DEFI-2026-REENTRANCY-01"
    assert in_dist[0].post_cutoff is False

    historical = loader.list_incidents(split="historical")
    assert len(historical) == 1
    assert historical[0].incident_id == "DEFI-2026-REENTRANCY-01"

    post_cutoff = loader.list_incidents(split="post_cutoff")
    assert len(post_cutoff) == 1
    assert post_cutoff[0].incident_id == "DEFI-2026-ACCESS-02"
    assert post_cutoff[0].post_cutoff is True


def test_loader_error_handling_and_schema_enforcement(tmp_path: Path) -> None:
    """Verify schema validation catches missing slots, unknown splits, and missing files."""
    loader = BenchmarkLoader()

    with pytest.raises(ValueError, match="Unknown split"):
        loader.list_incidents(split="invalid_split_name")

    with pytest.raises(KeyError, match="not found in manifest"):
        loader.load_incident("NON-EXISTENT-INCIDENT-999")

    # Missing required slot in GroundTruthAnnotation must raise ValueError
    with pytest.raises(ValueError, match="missing required RCA slots"):
        GroundTruthAnnotation(
            incident_id="BAD-GT-01",
            true_causal_factors=["Contract:fn:1"],
            plausible_non_causal_factors=[],
            expected_6_slots={
                "pre_attack_state": {},
                "attacker_input": {},
                # Missing vulnerable_operation, state_invariant_breakdown, asset_flow_impact, minimal_causal_chain
            },
        )

    # Duplicate incident_id in custom manifest must fail validate_manifest()
    bad_manifest = tmp_path / "incidents.json"
    bad_manifest.write_text(
        json.dumps(
            {
                "incidents": [
                    {
                        "incident_id": "DUP-01",
                        "protocol_name": "ProtoA",
                        "chain": "mainnet",
                        "fork_block": 100,
                        "target_contract": "0x1",
                        "vulnerability_class": "REENTRANCY",
                        "post_cutoff": False,
                    },
                    {
                        "incident_id": "DUP-01",
                        "protocol_name": "ProtoA",
                        "chain": "mainnet",
                        "fork_block": 100,
                        "target_contract": "0x1",
                        "vulnerability_class": "REENTRANCY",
                        "post_cutoff": False,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    bad_loader = BenchmarkLoader(manifest_path=bad_manifest, ground_truth_dir=tmp_path)
    with pytest.raises((ValueError, FileNotFoundError)):
        bad_loader.validate_manifest()

