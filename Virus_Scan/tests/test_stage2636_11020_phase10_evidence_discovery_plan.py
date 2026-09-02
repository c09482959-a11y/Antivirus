"""Phase 10: bounded model-assisted evidence discovery has zero authority."""
from __future__ import annotations

from dataclasses import fields
from pathlib import Path

import pytest

from Virus_Scan.contracts.artifact_evidence_snapshot import ArtifactEvidenceSnapshot
from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.evidence_discovery_plan import (
    EVIDENCE_DISCOVERY_QUERY_KINDS,
    EvidenceDiscoveryBudget,
    EvidenceDiscoveryPlan,
)
from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.tests.support.model_context_fixtures import model_projection_identity_fixture
from Virus_Scan.contracts.yara_hits import unavailable_yara_scan_result
from Virus_Scan.detection.attack.candidate_retrieval import (
    AttackCandidateRank,
    AttackCandidateRetrievalResult,
    AttackClusterContext,
    unavailable_attack_candidate_retrieval,
)
from Virus_Scan.detection.attack.evidence_discovery import build_evidence_discovery_plan
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.registries.chain_registry import CHAIN_REGISTRY_DIGEST, CHAIN_REGISTRY_VERSION


def _evidence(tmp_path: Path) -> ArtifactEvidenceSnapshot:
    path = tmp_path / "phase10.bin"
    path.write_bytes(b"phase10-artifact\n")
    return ArtifactEvidenceSnapshot(
        artifact_read_snapshot=build_artifact_read_snapshot(path),
        physical_observations=(),
        static_program_analyses=(),
        yara_scan_result=unavailable_yara_scan_result("yara_disabled", status="disabled"),
        tag_evidence=TagEvidence(),
        chain_evidence=ChainEvidence(CHAIN_REGISTRY_VERSION, CHAIN_REGISTRY_DIGEST),
        parser_analysis_limitations=("provisional_static_refinement_pending",),
        evidence_completeness="partial",
    )


def _context(evidence: ArtifactEvidenceSnapshot, *, extreme: float = 0.0) -> ModelContextSnapshot:
    return ModelContextSnapshot(
        projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest=evidence.semantic_digest,
        graph_features={"risk": extreme},
        temporal_features={"belief": extreme},
        markov_features={"rarity": extreme},
        cluster_context={"cluster_id": "phase10"},
    )


def _candidate(technique_id: str = "T1055", *, score: float = 1.0) -> AttackCandidateRetrievalResult:
    cluster = AttackClusterContext(
        cluster_id="phase10", cluster_model_version="phase10-model",
        cluster_members=10, trusted_support=10, maturity=1.0, purity=1.0,
        drift=0.0, cluster_quality=1.0, tag_signature=(), chain_signature=(),
        behavior_signature=(), available=True, unavailable_reason="",
    )
    rank = AttackCandidateRank(
        rank=1, technique_id=technique_id,
        implementation_ids=("local.t1055.process_injection",),
        claim_scopes=("artifact_implementation",), admission_state="candidate_only",
        correlation_group="injection", score=score,
        matched_cluster_chain_ids=(), matched_direct_chain_ids=(),
        shared_physical_root_ids=(), missing_direct_requirements=("chain:missing",),
    )
    return AttackCandidateRetrievalResult(
        repository_digest="c" * 64, dataset_version="phase10-dataset",
        cluster_context=cluster, tag_signatures=(), chain_signatures=(),
        static_operation_signatures=(), markov_context_signal=1.0,
        temporal_context_signal=1.0, candidates=(rank,), abstained=False,
        unavailable_reason="",
    )


def _plan(
    evidence: ArtifactEvidenceSnapshot,
    context: ModelContextSnapshot,
    candidate: AttackCandidateRetrievalResult,
    *,
    capabilities: tuple[str, ...] = tuple(sorted(EVIDENCE_DISCOVERY_QUERY_KINDS)),
    query_count: int = 4096,
    cost: int = 1_000_000,
) -> EvidenceDiscoveryPlan:
    return build_evidence_discovery_plan(
        evidence, context, candidate,
        frontend_capability_query_kinds=capabilities,
        resource_budget=EvidenceDiscoveryBudget(query_count, cost),
    )


def _search_space(plan: EvidenceDiscoveryPlan) -> set[tuple[str, str, str, str, str]]:
    return {
        (item.technique_id, item.implementation_id, item.chain_id, item.requirement_id, item.query_kind)
        for item in plan.queries
    }


def test_phase10_plan_is_context_only_and_registry_complete(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    plan = _plan(evidence, _context(evidence), unavailable_attack_candidate_retrieval("no_candidate"))
    record = plan.to_record()
    techniques = {item.technique_id for item in plan.queries}
    assert techniques == {"T1003", "T1021", "T1055", "T1059.001", "T1105"}
    assert "T1041" not in techniques and "T1562.001" not in techniques
    assert plan.requirement_ids
    assert set(plan.selected_query_ids) == {item.query_id for item in plan.queries}
    assert record["evidence_authority"] == "context_only"
    assert record["official_decision_effect"] == "none"
    names = {item.name for item in fields(EvidenceDiscoveryPlan)}
    for forbidden in (
        "tag_evidence", "chain_evidence", "physical_root_ids", "physical_observations",
        "static_program_analyses", "attack_mapping_result", "technique_decisions",
    ):
        assert forbidden not in names


def test_phase10_candidate_context_can_reorder_but_cannot_change_search_space(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    baseline_context = _context(evidence, extreme=0.0)
    extreme_context = _context(evidence, extreme=1.0)
    baseline = _plan(
        evidence, baseline_context,
        unavailable_attack_candidate_retrieval("models_disabled"),
    )
    boosted = _plan(evidence, extreme_context, _candidate("T1055", score=1.0))
    assert _search_space(baseline) == _search_space(boosted)
    assert baseline.requirement_ids == boosted.requirement_ids
    assert [item.query_id for item in baseline.queries] != [item.query_id for item in boosted.queries]
    assert boosted.queries[0].technique_id == "T1055"
    assert all(item.execution_state == "selected" for item in boosted.queries)


def test_phase10_budget_defers_without_dropping_required_searches(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    full = _plan(evidence, _context(evidence), _candidate(), query_count=4096, cost=1_000_000)
    bounded = _plan(evidence, _context(evidence), _candidate(), query_count=2, cost=4)
    assert _search_space(full) == _search_space(bounded)
    assert full.requirement_ids == bounded.requirement_ids
    assert len(bounded.selected_query_ids) <= 2
    assert bounded.unavailable_requirement_ids
    assert any(item.execution_state == "deferred_resource_budget" for item in bounded.queries)
    assert all(
        item.requirement_id in bounded.requirement_ids
        for item in bounded.queries if item.execution_state == "deferred_resource_budget"
    )


def test_phase10_frontend_capability_gaps_are_visible_not_silently_omitted(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    full = _plan(evidence, _context(evidence), _candidate())
    limited = _plan(
        evidence, _context(evidence), _candidate(),
        capabilities=("resolve_required_operation",),
    )
    assert _search_space(full) == _search_space(limited)
    assert any(item.execution_state == "deferred_frontend_capability" for item in limited.queries)
    assert all(
        item.execution_state == "selected"
        for item in limited.queries if item.query_kind == "resolve_required_operation"
    )
    assert limited.unavailable_requirement_ids


def test_phase10_model_context_must_bind_exact_provisional_evidence(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    other_path = tmp_path / "other"
    other_path.write_bytes(b"other\n")
    other = ArtifactEvidenceSnapshot(
        artifact_read_snapshot=build_artifact_read_snapshot(other_path),
        physical_observations=(), static_program_analyses=(),
        yara_scan_result=unavailable_yara_scan_result("yara_disabled", status="disabled"),
        tag_evidence=TagEvidence(),
        chain_evidence=ChainEvidence(CHAIN_REGISTRY_VERSION, CHAIN_REGISTRY_DIGEST),
        parser_analysis_limitations=(), evidence_completeness="partial",
    )
    with pytest.raises(ValueError, match="evidence_discovery_model_context_source_mismatch"):
        _plan(evidence, _context(other), _candidate())


def test_phase10_plan_is_deterministic_and_ignores_unknown_candidate_techniques(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    context = _context(evidence)
    baseline = _plan(evidence, context, unavailable_attack_candidate_retrieval("none"))
    # An invented model/candidate technique can never enter the registry-owned search space.
    invented = _plan(evidence, context, _candidate("T9999", score=1.0))
    repeated = _plan(evidence, context, unavailable_attack_candidate_retrieval("none"))
    assert _search_space(invented) == _search_space(baseline)
    assert all(item.technique_id != "T9999" for item in invented.queries)
    assert repeated.semantic_digest == baseline.semantic_digest
    assert repeated.to_record() == baseline.to_record()
