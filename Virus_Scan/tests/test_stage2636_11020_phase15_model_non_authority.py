"""Phase 15: adversarial model/context values have zero ATT&CK authority."""
from __future__ import annotations

from dataclasses import fields
from inspect import signature
from pathlib import Path

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.evidence_discovery_plan import (
    EVIDENCE_DISCOVERY_QUERY_KINDS,
    EvidenceDiscoveryBudget,
)
from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.tests.support.model_context_fixtures import model_projection_identity_fixture
from Virus_Scan.contracts.static_program_analysis import StaticProgramAnalysis, static_artifact_identity
from Virus_Scan.contracts.yara_hits import unavailable_yara_scan_result
from Virus_Scan.detection.attack.candidate_retrieval import (
    AttackCandidateRank,
    AttackCandidateRetrievalResult,
    AttackClusterContext,
    unavailable_attack_candidate_retrieval,
)
from Virus_Scan.detection.attack.evaluation_stage import evaluate_final_attack_mapping
from Virus_Scan.detection.attack.evidence_discovery import build_evidence_discovery_plan
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICY_BY_ID
from Virus_Scan.detection.evidence.artifact_session import ArtifactEvidenceSession
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.registries.chain_registry import CHAIN_REGISTRY_DIGEST, CHAIN_REGISTRY_VERSION
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import (
    attack_chain_contract_fixture,
    attack_contract_repository,
    attack_mapping_evidence_fixture,
)


_FULL_BUDGET = EvidenceDiscoveryBudget(4096, 1_000_000)
_ALL_CAPABILITIES = tuple(sorted(EVIDENCE_DISCOVERY_QUERY_KINDS))
_INVENTED_TECHNIQUE_ID = "T9999"


def _fixed_evidence():
    policy = ATTACK_TECHNIQUE_POLICY_BY_ID["T1003"]
    chains = attack_chain_contract_fixture(
        policy, "phase15-fixed-evidence", status="confirmed", root_count=2,
    )
    return attack_mapping_evidence_fixture(TagEvidence(), chains)


def _lifecycle_evidence(tmp_path: Path):
    target = tmp_path / "phase15-lifecycle.py"
    target.write_bytes(b"print('phase15 lifecycle')\n")
    read_snapshot = build_artifact_read_snapshot(target)
    analysis = StaticProgramAnalysis(
        content_sha256=read_snapshot.content_sha256, content_size=read_snapshot.size,
        artifact_identity=static_artifact_identity(read_snapshot.content_sha256),
        language="python", language_version="3", parser_status="complete",
        parser_schema_version="phase15_static_fixture_v1", parser_digest="b" * 64,
        operations=(), flow_edges=(), entrypoint_function_ids=(),
        unresolved_constructs=(), limitations=(), integrity_status="verified",
    )
    session = ArtifactEvidenceSession(
        artifact_read_snapshot=read_snapshot, static_program_analyses=(analysis,),
        yara_scan_result=unavailable_yara_scan_result("yara_disabled", status="disabled"),
    )
    return session.provisional_evidence(
        tag_evidence=TagEvidence(),
        chain_evidence=ChainEvidence(CHAIN_REGISTRY_VERSION, CHAIN_REGISTRY_DIGEST),
    )


def _context(evidence, *, extreme: float, invented: bool) -> ModelContextSnapshot:
    technique = _INVENTED_TECHNIQUE_ID if invented else "T1055"
    return ModelContextSnapshot(
        projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest=evidence.semantic_digest,
        graph_features={"risk": extreme, "technique_id": technique},
        temporal_features={"belief": extreme, "technique_id": technique},
        markov_features={"rarity": extreme, "technique_id": technique},
        engine_context={"confidence": extreme, "technique_id": technique},
        profile_context={"attack_intelligence": {"confidence": extreme, "technique_id": technique}},
        behavior_flow=({"probability": extreme, "technique_id": technique},),
        feature_vector=(extreme, 1.0 - extreme),
        cluster_context={"similarity": extreme, "technique_id": technique},
        attack_family_classifier_context={"probability": extreme, "technique_id": technique},
    )


def _candidate(technique_id: str) -> AttackCandidateRetrievalResult:
    cluster = AttackClusterContext(
        cluster_id="phase15", cluster_model_version="phase15-model",
        cluster_members=10, trusted_support=10, maturity=1.0, purity=1.0,
        drift=0.0, cluster_quality=1.0, tag_signature=(), chain_signature=(),
        behavior_signature=(), available=True, unavailable_reason="",
    )
    rank = AttackCandidateRank(
        rank=1, technique_id=technique_id,
        implementation_ids=("local.t1055.process_injection",),
        claim_scopes=("artifact_implementation",), admission_state="candidate_only",
        correlation_group="injection", score=1.0,
        matched_cluster_chain_ids=(), matched_direct_chain_ids=(),
        shared_physical_root_ids=(), missing_direct_requirements=("chain:missing",),
    )
    return AttackCandidateRetrievalResult(
        repository_digest="c" * 64, dataset_version="phase15-dataset",
        cluster_context=cluster, tag_signatures=(), chain_signatures=(),
        static_operation_signatures=(), markov_context_signal=1.0,
        temporal_context_signal=1.0, candidates=(rank,), abstained=False,
        unavailable_reason="",
    )


def _plan(evidence, context, candidate):
    return build_evidence_discovery_plan(
        evidence, context, candidate,
        frontend_capability_query_kinds=_ALL_CAPABILITIES,
        resource_budget=_FULL_BUDGET,
    )


def _search_space(plan) -> set[tuple[str, str, str, str, str]]:
    return {
        (row.technique_id, row.implementation_id, row.chain_id, row.requirement_id, row.query_kind)
        for row in plan.queries
    }


def _final_evidence(base, context, candidate):
    session = ArtifactEvidenceSession(
        artifact_read_snapshot=base.artifact_read_snapshot,
        static_program_analyses=base.static_program_analyses,
        yara_scan_result=base.yara_scan_result,
    )
    provisional = session.provisional_evidence(
        tag_evidence=base.tag_evidence, chain_evidence=base.chain_evidence,
    )
    rebound = _context(provisional, extreme=context[0], invented=context[1])
    session.bind_model_context(rebound)
    plan = _plan(provisional, rebound, candidate)
    session.bind_discovery_plan(plan)
    session.refine()
    final = session.freeze_final(
        tag_evidence=base.tag_evidence, chain_evidence=base.chain_evidence,
    )
    return final, plan


def _contains_text(value: object, needle: str) -> bool:
    if type(value) is dict:
        return any(_contains_text(key, needle) or _contains_text(item, needle) for key, item in value.items())
    if type(value) in (tuple, list):
        return any(_contains_text(item, needle) for item in value)
    return value == needle


def test_phase15_model_context_contract_cannot_own_attack_evidence_or_mapping() -> None:
    names = {item.name for item in fields(ModelContextSnapshot)}
    assert tuple(signature(map_attack_evidence).parameters) == ("snapshot", "evidence")
    assert tuple(signature(evaluate_final_attack_mapping).parameters) == ("evidence",)
    for forbidden in (
        "tag_evidence", "chain_evidence", "physical_observations", "physical_root_ids",
        "attack_mapping_result", "technique_decisions", "requirement_satisfaction",
    ):
        assert forbidden not in names


def test_phase15_all_adversarial_model_families_leave_fixed_mapping_bit_identical() -> None:
    evidence = _fixed_evidence()
    low = _context(evidence, extreme=0.0, invented=False)
    high = _context(evidence, extreme=1.0, invented=True)
    assert low.semantic_digest != high.semantic_digest
    assert high.to_record()["evidence_authority"] == "context_only"
    assert high.to_record()["official_decision_effect"] == "none"
    assert _contains_text(high.to_record(), _INVENTED_TECHNIQUE_ID)
    baseline = map_attack_evidence(attack_contract_repository(), evidence)
    assert map_attack_evidence(attack_contract_repository(), evidence).to_record() == baseline.to_record()
    assert not _contains_text(baseline.to_record(), _INVENTED_TECHNIQUE_ID)


def test_phase15_invented_candidate_cannot_enter_registry_owned_search_space() -> None:
    evidence = _fixed_evidence()
    context = _context(evidence, extreme=1.0, invented=True)
    baseline = _plan(evidence, context, unavailable_attack_candidate_retrieval("models_disabled"))
    invented = _plan(evidence, context, _candidate(_INVENTED_TECHNIQUE_ID))
    assert _search_space(invented) == _search_space(baseline)
    assert invented.requirement_ids == baseline.requirement_ids
    assert all(row.technique_id != _INVENTED_TECHNIQUE_ID for row in invented.queries)


def test_phase15_full_budget_reordering_converges_on_identical_final_evidence(tmp_path: Path) -> None:
    base = _lifecycle_evidence(tmp_path)
    baseline, baseline_plan = _final_evidence(
        base, (0.0, False), unavailable_attack_candidate_retrieval("models_disabled"),
    )
    boosted, boosted_plan = _final_evidence(base, (1.0, True), _candidate("T1055"))
    assert _search_space(baseline_plan) == _search_space(boosted_plan)
    assert [row.query_id for row in baseline_plan.queries] != [row.query_id for row in boosted_plan.queries]
    assert baseline.semantic_digest == boosted.semantic_digest
    assert baseline.to_record() == boosted.to_record()


def test_phase15_full_budget_model_context_cannot_change_official_attack_result(tmp_path: Path) -> None:
    base = _lifecycle_evidence(tmp_path)
    low, _ = _final_evidence(
        base, (0.0, False), unavailable_attack_candidate_retrieval("models_disabled"),
    )
    high, _ = _final_evidence(base, (1.0, True), _candidate(_INVENTED_TECHNIQUE_ID))
    low_result = map_attack_evidence(attack_contract_repository(), low)
    high_result = map_attack_evidence(attack_contract_repository(), high)
    assert low.semantic_digest == high.semantic_digest
    assert low_result.to_record() == high_result.to_record()
    assert not _contains_text(high.to_record(), _INVENTED_TECHNIQUE_ID)
    assert not _contains_text(high_result.to_record(), _INVENTED_TECHNIQUE_ID)
