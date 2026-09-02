"""Phase 9/18: probabilistic context cannot own or manufacture ATT&CK evidence."""
from __future__ import annotations

from dataclasses import fields
from inspect import signature
from pathlib import Path

from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.detection.attack.candidate_retrieval import (
    rank_attack_candidates,
    retrieve_current_attack_candidates,
)
from Virus_Scan.detection.models.enriched_stage_outputs import (
    DetectionEvidenceFacts,
    EnrichedDetectionFacts,
)
from Virus_Scan.detection.scoring.full_analysis.input_builder import ScoreContextRequest
from Virus_Scan.tests.support.model_context_fixtures import model_context_snapshot_fixture


def test_phase9_model_context_snapshot_is_context_only_by_type_and_record() -> None:
    forbidden_authority_fields = {
        "tag_evidence", "chain_evidence", "physical_root_ids", "static_program_analyses",
        "attack_mapping_result", "attack_techniques", "technique_ids",
    }
    names = {field.name for field in fields(ModelContextSnapshot)}
    assert {"source_artifact_evidence_digest", "projection_identity", "failure_evidence"} <= names
    assert names.isdisjoint(forbidden_authority_fields)
    record = model_context_snapshot_fixture(
        graph_features={"risk": 1.0}, temporal_features={"belief": 1.0},
        markov_features={"transition": 1.0}, behavior_flow=("model_sequence_only",),
        cluster_id="adversarial-context",
    ).to_record()
    assert record["evidence_authority"] == "context_only"
    assert record["official_decision_effect"] == "none"
    assert set(record).isdisjoint(forbidden_authority_fields)


def test_phase9_authoritative_evidence_and_model_context_have_separate_owners() -> None:
    evidence_names = {field.name for field in fields(DetectionEvidenceFacts)}
    enriched_names = {field.name for field in fields(EnrichedDetectionFacts)}
    assert {"tag_evidence", "chain_evidence"} <= evidence_names
    assert enriched_names == {"evidence", "model_context", "failure_evidence"}
    assert "tag_evidence" not in {field.name for field in fields(ModelContextSnapshot)}
    assert "chain_evidence" not in {field.name for field in fields(ModelContextSnapshot)}


def test_phase9_scoring_accepts_only_explicit_evidence_not_model_context() -> None:
    names = set(signature(ScoreContextRequest).parameters)
    assert {"tag_evidence", "chain_evidence"} <= names
    assert "model_context" not in names


def test_phase9_candidate_retrieval_reads_evidence_explicitly_and_context_separately() -> None:
    ranked = tuple(signature(rank_attack_candidates).parameters)
    current = tuple(signature(retrieve_current_attack_candidates).parameters)
    assert ranked[:4] == ("tag_evidence", "chain_evidence", "model_context", "cluster_context")
    assert current[:4] == ("node", "tag_evidence", "chain_evidence", "model_context")


def test_phase9_chain_evaluator_has_no_model_context_or_behavior_flow_authority() -> None:
    source = Path("Virus_Scan/detection/chains/execution/anchors.py").read_text(encoding="utf-8")
    assert "ModelContextSnapshot" not in source
    assert "behavior_flow" not in source
