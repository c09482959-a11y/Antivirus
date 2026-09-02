"""Stage 1396: context-confidence model evidence uses canonical terms only."""

from __future__ import annotations

from Virus_Scan.detection.scoring.weighting.context_confidence import (
    compute_context_confidence_amplifier,
)
from Virus_Scan.detection.scoring.weighting import policy_constants
from Virus_Scan.scanners.config.loader import load_text_policy_snapshot
import Virus_Scan.scanners.text_policy as text_policy
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_stage1396_context_corroboration_output_uses_canonical_model_evidence_terms():
    result = compute_context_confidence_amplifier(
        "node-a",
        physical_tag_evidence(("cmd_exec", "network_download", "powershell_exec")),
        
        {"graph": {"score": 100.0}, "intel": {"score": 100.0}},
        adaptive_learning={"markov": {"markov_anomaly": 1.0}},
        pre_context_score=60.0,
    )

    assert result["context_corroboration_bonus_raw"] > 0.0
    assert "_".join(("gnn", "siem", "bonus", "raw")) not in result
    assert any(hit.startswith("context_model_corroboration:+") for hit in result["hits"])
    assert not any("gnn" in hit.lower() or "siem" in hit.lower() for hit in result["hits"])
    assert "context_corroboration_max_bonus" in result["caps"]
    assert "_".join(("gnn", "siem", "max", "bonus")) not in result["caps"]


def test_stage1396_context_policy_snapshot_uses_canonical_corroboration_field():
    snapshot = load_text_policy_snapshot()

    assert snapshot.context_corroboration_max_bonus == 10.0
    assert not hasattr(snapshot, "_".join(("gnn", "siem", "max", "bonus")))
    assert text_policy.CONTEXT_CORROBORATION_MAX_BONUS == snapshot.context_corroboration_max_bonus
    assert not hasattr(text_policy, "_".join(("gnn", "siem", "max", "bonus")).upper())
    assert policy_constants.CONTEXT_CORROBORATION_MAX_BONUS == 10.0
    assert not hasattr(policy_constants, "_".join(("gnn", "siem", "max", "bonus")).upper())
