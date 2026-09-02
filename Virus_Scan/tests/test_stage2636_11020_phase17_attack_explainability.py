"""Phase 17: final ATT&CK publication exposes authority without gaining authority."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from Virus_Scan.contracts.artifact_evidence_snapshot import ArtifactEvidenceSnapshot
from Virus_Scan.detection.attack.explainability import (
    AttackExplainabilitySnapshot,
    build_attack_explainability,
)
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import (
    attack_chain_contract_fixture,
    attack_contract_repository,
    attack_explainability_context_fixture,
    attack_mapping_evidence_fixture,
)
from Virus_Scan.tests.support.canonical_yara_fixtures import canonical_test_yara_result


def _t1055_evidence_and_mapping() -> tuple[ArtifactEvidenceSnapshot, object]:
    policy = next(item for item in ATTACK_TECHNIQUE_POLICIES if item.technique_id == "T1055")
    chains = attack_chain_contract_fixture(
        policy, "phase17", status="confirmed", root_count=3,
    )
    evidence = attack_mapping_evidence_fixture(TagEvidence.from_records(()), chains)
    mapping = map_attack_evidence(attack_contract_repository(), evidence)
    return evidence, mapping


def test_phase17_decision_local_authority_chain_is_complete_and_non_authoritative() -> None:
    evidence, mapping = _t1055_evidence_and_mapping()
    candidate, plan, snapshot = attack_explainability_context_fixture(evidence, mapping)
    record = snapshot.to_record()
    decision = next(item for item in record["decisions"] if item["technique_id"] == "T1055")

    official = next(item for item in mapping.decisions if item.technique_id == "T1055")
    assert decision["status"] == official.status == "candidate"
    assert decision["claim_scopes"] == list(official.claim_scopes) == ["artifact_implementation"]
    assert decision["execution_observed"] is False
    assert {item["root_evidence_id"] for item in decision["physical_roots"]} == set(
        official.root_evidence_ids
    )
    assert len(decision["requirements"]) == 1
    requirement = decision["requirements"][0]
    assert requirement["chain_id"] == "static.artifact.virtualallocex_writeprocessmemory_createremotethread"
    assert requirement["satisfied"] is True
    assert len(requirement["matched_steps"]) == 3
    assert set(requirement["root_evidence_ids"]) == set(official.root_evidence_ids)
    assert len(requirement["relation_requirements"]) == 2
    assert all(item["require_data_flow_path"] is True for item in requirement["relation_requirements"])
    assert all(item["same_resource"] is True for item in requirement["relation_requirements"])
    assert decision["yara"]["role"] == "absent"
    assert decision["model_assistance"]["evidence_authority"] == "context_only"
    assert decision["model_assistance"]["official_decision_effect"] == "none"
    assert record["projection_role"] == "explainability_only"
    assert record["official_decision_effect"] == "none"
    assert candidate.to_record()["official_decision_effect"] == "none"
    assert plan.to_record()["official_decision_effect"] == "none"


def test_phase17_physical_yara_hit_not_used_by_decision_is_published_as_not_used() -> None:
    evidence, _mapping = _t1055_evidence_and_mapping()
    yara = canonical_test_yara_result(artifact_digest=evidence.artifact_read_snapshot.content_sha256)
    with_yara = ArtifactEvidenceSnapshot(
        artifact_read_snapshot=evidence.artifact_read_snapshot,
        physical_observations=evidence.physical_observations,
        static_program_analyses=evidence.static_program_analyses,
        yara_scan_result=yara,
        tag_evidence=evidence.tag_evidence,
        chain_evidence=evidence.chain_evidence,
        parser_analysis_limitations=evidence.parser_analysis_limitations,
        evidence_completeness=evidence.evidence_completeness,
        deterministic_derivations=evidence.deterministic_derivations,
    )
    mapping = map_attack_evidence(attack_contract_repository(), with_yara)
    _candidate, _plan, snapshot = attack_explainability_context_fixture(with_yara, mapping)
    decision = next(item for item in snapshot.to_record()["decisions"] if item["technique_id"] == "T1055")
    assert decision["yara"]["role"] == "not_used"
    assert decision["yara"]["physical_hit_count"] == 1
    assert decision["yara"]["verified_hit_count"] == 1
    assert decision["yara"]["used_root_evidence_ids"] == []


def test_phase17_snapshot_rejects_tampered_semantic_digest() -> None:
    evidence, mapping = _t1055_evidence_and_mapping()
    _candidate, _plan, snapshot = attack_explainability_context_fixture(evidence, mapping)
    try:
        replace(snapshot, semantic_digest="0" * 64)
    except ValueError as exc:
        assert str(exc) == "attack_explainability_semantic_digest_mismatch"
    else:
        raise AssertionError("tampered explainability digest accepted")


def test_phase17_explainability_module_is_projection_only() -> None:
    source = Path("Virus_Scan/detection/attack/explainability.py").read_text(encoding="utf-8")
    forbidden = (
        "map_attack_evidence(",
        "evaluate_chain_evidence(",
        "yara_scan(",
        "analyze_native_elf_x86_64_snapshot(",
        "analyze_python_renpy_snapshot(",
    )
    assert all(item not in source for item in forbidden)
    pipeline = Path(
        "Virus_Scan/detection/orchestration/full_analysis/pipeline_execution.py"
    ).read_text(encoding="utf-8")
    assert pipeline.count("build_attack_explainability(") == 1
    assert "evidence_lifecycle.final_evidence" in pipeline
    assert "evidence_lifecycle.discovery_plan" in pipeline
