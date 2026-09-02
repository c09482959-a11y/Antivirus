from dataclasses import FrozenInstanceError

import pytest

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.registries.chain_registry import CANONICAL_CHAIN_RULES
from Virus_Scan.detection.scoring.weighting.chain_bonus import calibrated_chain_bonus
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_stage1006_lolbin_policy_is_owned_by_frozen_canonical_rules():
    rules = tuple(rule for rule in CANONICAL_CHAIN_RULES if rule.family == "lolbin_abuse")
    assert rules
    with pytest.raises(FrozenInstanceError):
        rules[0].score_points = 0.0


def test_stage1006_lolbin_detection_uses_canonical_candidate_decisions():
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence((
        "network_download", "file_write", "process_exec",
        "scheduled_task", "schtasks_create",
    )))
    score, hits = calibrated_chain_bonus(evidence)

    assert score > 0.0
    assert evidence.decisions
    assert all(hit.startswith("chain_bonus:") for hit in hits)
    assert any(
        decision.candidate.family in {"download_execute", "persistence_execution"}
        for decision in evidence.decisions
        if decision.scoreable
    )
