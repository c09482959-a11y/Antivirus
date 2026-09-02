"""Phase 11: one bounded artifact-evidence lifecycle and final freeze."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.evidence_discovery_plan import EvidenceDiscoveryBudget
from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.tests.support.model_context_fixtures import model_projection_identity_fixture
from Virus_Scan.contracts.yara_hits import unavailable_yara_scan_result
from Virus_Scan.detection.attack.candidate_retrieval import unavailable_attack_candidate_retrieval
from Virus_Scan.detection.attack.evidence_discovery import build_evidence_discovery_plan
from Virus_Scan.detection.evidence.artifact_session import ArtifactEvidenceSession
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.registries.chain_registry import CHAIN_REGISTRY_DIGEST, CHAIN_REGISTRY_VERSION


def _chain_evidence() -> ChainEvidence:
    return ChainEvidence(CHAIN_REGISTRY_VERSION, CHAIN_REGISTRY_DIGEST)


def test_phase11_session_has_one_bounded_freeze_and_one_way_context_binding(tmp_path: Path) -> None:
    target = tmp_path / "phase11.bin"
    target.write_bytes(b"phase11-lifecycle\n")
    session = ArtifactEvidenceSession(
        artifact_read_snapshot=build_artifact_read_snapshot(target),
        static_program_analyses=(),
        yara_scan_result=unavailable_yara_scan_result("yara_disabled", status="disabled"),
    )
    provisional = session.provisional_evidence(
        tag_evidence=TagEvidence(),
        chain_evidence=_chain_evidence(),
    )
    context = ModelContextSnapshot(
        projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest=provisional.semantic_digest,
        graph_features={"risk": 1.0},
        temporal_features={"belief": 1.0},
        markov_features={"rarity": 1.0},
    )
    session.bind_model_context(context)
    plan = build_evidence_discovery_plan(
        provisional,
        context,
        unavailable_attack_candidate_retrieval("models_disabled"),
        frontend_capability_query_kinds=(),
        resource_budget=EvidenceDiscoveryBudget(4096, 1_000_000),
    )
    session.bind_discovery_plan(plan)
    limitations = session.refine()
    final = session.freeze_final(
        tag_evidence=TagEvidence(),
        chain_evidence=_chain_evidence(),
    )

    assert session.frozen is True
    assert context.source_artifact_evidence_digest == provisional.semantic_digest
    assert plan.source_artifact_evidence_digest == provisional.semantic_digest
    assert plan.model_context_digest == context.semantic_digest
    assert plan.to_record()["evidence_authority"] == "context_only"
    assert plan.to_record()["official_decision_effect"] == "none"
    assert limitations
    assert final.parser_analysis_limitations == limitations
    assert final.semantic_digest != provisional.semantic_digest
    assert final.to_record()["evidence_authority"] == "physical_and_deterministic_only"

    with pytest.raises(RuntimeError, match="artifact_evidence_session_refinement_state_invalid"):
        session.refine()
    with pytest.raises(RuntimeError, match="artifact_evidence_session_freeze_state_invalid"):
        session.freeze_final(tag_evidence=TagEvidence(), chain_evidence=_chain_evidence())
    with pytest.raises(FrozenInstanceError):
        final.evidence_completeness = "complete"  # type: ignore[misc]


def test_phase11_production_lifecycle_freezes_before_scoring_and_never_rescans() -> None:
    pipeline = Path("Virus_Scan/detection/orchestration/full_analysis/pipeline.py").read_text(encoding="utf-8")
    session_source = Path("Virus_Scan/detection/evidence/artifact_session.py").read_text(encoding="utf-8")
    success_source = Path("Virus_Scan/detection/orchestration/full_analysis/pipeline_execution.py").read_text(encoding="utf-8")

    assert pipeline.index("build_artifact_evidence_lifecycle(") < pipeline.index("score_full_analysis_context(")
    assert "STATIC_PROGRAM_ANALYSIS_FRONTENDS" not in session_source
    assert ".analyzer(" not in session_source
    assert session_source.count("retrieve_current_attack_candidates(") == 1
    assert "retrieve_current_attack_candidates(" not in success_source
    assert "attack_candidate_retrieval=evidence_lifecycle.candidate_retrieval.to_record()" in success_source


def test_phase11_scheduler_propagates_exact_router_static_analysis_without_second_owner() -> None:
    job = Path("Virus_Scan/scheduler/execution/scheduler_file_job.py").read_text(encoding="utf-8")
    analysis = Path("Virus_Scan/scheduler/execution/scheduler_file_analysis.py").read_text(encoding="utf-8")
    record_steps = Path("Virus_Scan/scheduler/execution/scheduler_file_analysis_record_steps.py").read_text(encoding="utf-8")
    inmemory = Path("Virus_Scan/scheduler/workers/inmemory_file_scan_steps.py").read_text(encoding="utf-8")

    assert "route_static_program_analyses=route_outcome.static_program_analyses" in job
    assert "route_static_program_analyses=route_static_program_analyses" in analysis
    assert "static_program_analyses=route_static_program_analyses" in record_steps
    # The process/in-memory worker enters the same canonical scheduler file owner;
    # it does not own an alternate full-analysis/static-analysis pipeline.
    assert "execute_scheduler_file_with_cache(" in inmemory
    assert "analyze_file_full_observe_only(" not in inmemory
