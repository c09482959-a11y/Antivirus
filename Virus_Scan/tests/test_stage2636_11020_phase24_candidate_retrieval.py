"""Phase 24 cluster-assisted ATT&CK candidate retrieval contracts."""
from __future__ import annotations

from Virus_Scan.tests.support.attack_mapping_contract_fixtures import attack_mapping_evidence_fixture

import pytest

from Virus_Scan.contracts.detection_observation import DetectionObservation, ObservationSourceLocation
from Virus_Scan.detection.attack.candidate_retrieval import (
    AttackClusterContext, rank_attack_candidates, unavailable_attack_candidate_retrieval,
)
from Virus_Scan.detection.attack.candidate_retrieval_evaluation import (
    AttackCandidateEvaluationSample, evaluate_attack_candidate_retrieval,
)
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICY_BY_ID
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.tests.support.model_context_fixtures import model_context_snapshot_fixture
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.registries.chain_registry import CHAIN_RULE_INDEX
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import (
    attack_chain_contract_fixture, attack_contract_repository,
)

_HEX = "a" * 64



def _tags() -> TagEvidence:
    observation = DetectionObservation.create(
        tag="static_process_open_operation",
        producer_id="python_renpy_static_analysis",
        stage_id="static_operation_projection",
        modality="static_control_flow",
        platform="windows",
        artifact_identity="artifact:phase24",
        source_location=ObservationSourceLocation(
            "ast", locator="phase24.py", event_id="line:1:column:0",
        ),
        integrity_status="verified",
        directness="direct",
        confidence=1.0,
    )
    return normalize_tag_evidence(
        (observation,),
        source_detector="python_renpy_static_analysis",
        source_stage="static_operation_projection",
    )


def _evidence():
    tags = _tags()
    policy = ATTACK_TECHNIQUE_POLICY_BY_ID["T1003"]
    chains = attack_chain_contract_fixture(policy, "phase24", status="candidate", root_count=1)
    return tags, chains


def _model_context(*, markov: float = 0.0, temporal: float = 0.0) -> ModelContextSnapshot:
    return model_context_snapshot_fixture(
        markov_features={"rarity": markov}, temporal_features={"belief": temporal},
        engine_context={"other": 1.0}, cluster_id="phase24-cluster",
    )


def _cluster(*, drift: float = 0.0) -> AttackClusterContext:
    chain_id = "anchor:api_lsass_minidump"; rule = CHAIN_RULE_INDEX[chain_id]
    return AttackClusterContext(
        cluster_id="phase24-cluster", cluster_model_version="phase24-cluster-model",
        cluster_members=24, trusted_support=16, maturity=1.0, purity=0.95, drift=drift,
        cluster_quality=0.9, tag_signature=("static_process_open_operation",),
        chain_signature=(f"candidate:{rule.family}:{chain_id}:{rule.version}",),
        behavior_signature=("credential_access",), available=True, unavailable_reason="",
    )


def _rank(model_context: ModelContextSnapshot, cluster: AttackClusterContext):
    tags, chains = _evidence()
    return rank_attack_candidates(tags, chains, model_context, cluster, repository_digest="c"*64, dataset_version="d"*40)


def test_phase24_candidate_retrieval_is_context_only_and_traceable() -> None:
    result = _rank(_model_context(markov=0.7, temporal=0.6), _cluster())
    record = result.to_record()
    assert result.abstained is False
    assert result.candidates[0].technique_id == "T1003"
    assert result.candidates[0].matched_cluster_chain_ids == ("anchor:api_lsass_minidump",)
    assert result.candidates[0].shared_physical_root_ids
    assert record["static_operation_signatures"] == ("static_process_open_operation",)
    assert record["evidence_authority"] == "context_only"
    assert record["official_decision_effect"] == "none"
    assert len(record["semantic_digest"]) == 64


def test_phase24_cluster_markov_temporal_context_cannot_change_official_mapping() -> None:
    tags, chains = _evidence(); model_a = _model_context(); model_b = _model_context(markov=1.0, temporal=1.0)
    repository = attack_contract_repository()
    official_a = map_attack_evidence(repository, attack_mapping_evidence_fixture(tags, chains)).to_record()
    official_b = map_attack_evidence(repository, attack_mapping_evidence_fixture(tags, chains)).to_record()
    candidate_a = rank_attack_candidates(tags, chains, model_a, _cluster(), repository_digest=repository.digest, dataset_version=repository.version.dataset_version)
    candidate_b = rank_attack_candidates(tags, chains, model_b, _cluster(), repository_digest=repository.digest, dataset_version=repository.version.dataset_version)
    assert official_a == official_b
    assert official_a["probability"] == 0.0
    assert candidate_a.candidates[0].score < candidate_b.candidates[0].score
    assert candidate_b.to_record()["eligible_for_probability"] is False


def test_phase24_retrieval_abstains_without_eligible_cluster_or_overlap() -> None:
    unavailable = unavailable_attack_candidate_retrieval("no_cluster")
    assert unavailable.abstained is True and unavailable.candidates == ()
    empty = AttackClusterContext(
        cluster_id="phase24-empty", cluster_model_version="phase24-model",
        cluster_members=20, trusted_support=20, maturity=1.0, purity=1.0, drift=0.0,
        cluster_quality=1.0, tag_signature=(), chain_signature=(), behavior_signature=(),
        available=True, unavailable_reason="",
    )
    result = _rank(_model_context(), empty)
    assert result.abstained is True
    assert result.unavailable_reason == "cluster_no_reviewed_candidate_overlap"


def test_phase24_evaluation_reports_recall_precision_mrr_abstention_and_drift() -> None:
    hit = _rank(_model_context(), _cluster()); miss = unavailable_attack_candidate_retrieval("cluster_drifted")
    metrics = evaluate_attack_candidate_retrieval((
        AttackCandidateEvaluationSample("stable", ("T1003",), hit, False),
        AttackCandidateEvaluationSample("drifted", ("T1003",), miss, True),
    ), k=3)
    record = metrics.to_record()
    assert record["recall_at_k"] == 0.5
    assert record["precision_at_k"] == pytest.approx(1.0/6.0)
    assert record["mean_reciprocal_rank"] == 0.5
    assert record["abstention_rate"] == 0.5
    assert record["stable_recall_at_k"] == 1.0
    assert record["drifted_recall_at_k"] == 0.0
    assert record["drift_recall_delta"] == 1.0


def test_phase28_precision_at_k_uses_requested_k_for_short_rankings() -> None:
    metrics = evaluate_attack_candidate_retrieval((
        AttackCandidateEvaluationSample("short-ranking", ("T1003",), _rank(_model_context(), _cluster()), False),
    ), k=5)
    assert metrics.precision_at_k == pytest.approx(0.2)


def test_phase28_evaluation_rejects_unlabeled_duplicate_or_invalid_oracles() -> None:
    result = unavailable_attack_candidate_retrieval("no_cluster")
    with pytest.raises(ValueError, match="attack_candidate_evaluation_expected_invalid"):
        AttackCandidateEvaluationSample("empty", (), result)
    with pytest.raises(ValueError, match="attack_candidate_evaluation_expected_invalid"):
        AttackCandidateEvaluationSample("duplicate", ("T1003", "T1003"), result)
    with pytest.raises(ValueError, match="attack_candidate_evaluation_expected_invalid"):
        AttackCandidateEvaluationSample("invalid", ("not-a-technique",), result)
    with pytest.raises(ValueError, match="attack_candidate_evaluation_expected_invalid"):
        AttackCandidateEvaluationSample("tactic", ("TA0001",), result)
    with pytest.raises(TypeError, match="attack_candidate_evaluation_expected_invalid"):
        AttackCandidateEvaluationSample("list", ["T1003"], result)  # type: ignore[arg-type]
