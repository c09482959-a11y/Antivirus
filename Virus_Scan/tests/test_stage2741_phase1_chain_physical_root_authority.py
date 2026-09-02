"""Stage2741 Phase-1 regression: Chain authority requires physical roots."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.yara_hits import unavailable_yara_scan_result
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.evidence.artifact_session import ArtifactEvidenceSession
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_runtime_chain_event


def test_unrooted_timeline_correlation_is_context_only_and_snapshot_safe(tmp_path: Path) -> None:
    chain_evidence = evaluate_chain_evidence(
        ordered_events=(
            {"event": "network_download", "timestamp": 1.0},
            {"event": "process_exec", "timestamp": 2.0},
        ),
        match_modes=("ordered",),
    )
    decisions = tuple(
        decision for decision in chain_evidence.decisions
        if decision.candidate.chain_id in {
            "execution.download_before_execution", "execution.download_execute",
        }
    )
    assert decisions
    assert all(decision.status == "candidate" for decision in decisions)
    assert all(decision.scoreable is False for decision in decisions)
    assert all(decision.candidate.physically_rooted is False for decision in decisions)
    assert all(
        "physical_root_unavailable" in decision.candidate.unmet_requirements
        for decision in decisions
    )
    assert chain_evidence.scoreable_root_ids == frozenset()

    target = tmp_path / "timeline-context.txt"
    target.write_text("network_download process_exec", encoding="utf-8")
    session = ArtifactEvidenceSession(
        artifact_read_snapshot=build_artifact_read_snapshot(target),
        static_program_analyses=(),
        yara_scan_result=unavailable_yara_scan_result("yara_disabled", status="disabled"),
    )
    provisional = session.provisional_evidence(
        tag_evidence=TagEvidence(), chain_evidence=chain_evidence,
    )
    assert provisional.chain_evidence is chain_evidence
    assert provisional.chain_evidence.scoreable_root_ids == frozenset()


def test_attack_mapper_source_rejects_context_only_chain_roots() -> None:
    source = Path("Virus_Scan/detection/attack/mapping/mapper.py").read_text(encoding="utf-8")
    assert "if not decision.candidate.physically_rooted:" in source



def test_valid_looking_obs_ids_in_plain_mapping_have_zero_physical_authority(tmp_path: Path) -> None:
    chain_evidence = evaluate_chain_evidence(
        ordered_events=(
            {
                "event": "network_download",
                "timestamp": 1.0,
                "root_observation_id": "obs_" + "1" * 40,
                "observation_id": "obs_" + "a" * 40,
                "artifact_identity": "artifact:spoof",
            },
            {
                "event": "process_exec",
                "timestamp": 2.0,
                "root_observation_id": "obs_" + "2" * 40,
                "observation_id": "obs_" + "b" * 40,
                "artifact_identity": "artifact:spoof",
            },
        ),
        match_modes=("ordered",),
        rule_ids=("execution.download_execute",),
    )
    decision = next(item for item in chain_evidence.decisions if item.candidate.chain_id == "execution.download_execute")
    assert decision.status == "candidate"
    assert decision.scoreable is False
    assert decision.candidate.physically_rooted is False
    assert "physical_root_unavailable" in decision.candidate.unmet_requirements
    assert chain_evidence.scoreable_root_ids == frozenset()

    target = tmp_path / "spoof-safe.txt"
    target.write_text("network_download process_exec", encoding="utf-8")
    session = ArtifactEvidenceSession(
        artifact_read_snapshot=build_artifact_read_snapshot(target),
        static_program_analyses=(),
        yara_scan_result=unavailable_yara_scan_result("yara_disabled", status="disabled"),
    )
    snapshot = session.provisional_evidence(tag_evidence=TagEvidence(), chain_evidence=chain_evidence)
    assert snapshot.chain_evidence.scoreable_root_ids == frozenset()


def test_exact_detection_observations_are_physical_when_assimilated_into_tag_evidence(tmp_path: Path) -> None:
    observations = (
        physical_runtime_chain_event("network_download", 1.0, 0, source_detector="stage2741_runtime"),
        physical_runtime_chain_event("process_exec", 2.0, 1, source_detector="stage2741_runtime"),
    )
    tags = normalize_tag_evidence(
        observations,
        source_detector="stage2741_runtime",
        source_stage="runtime_observation",
    )
    chain_evidence = evaluate_chain_evidence(
        tags=tags,
        ordered_events=observations,
        match_modes=("ordered",),
        rule_ids=("execution.download_execute",),
    )
    decision = next(item for item in chain_evidence.decisions if item.candidate.chain_id == "execution.download_execute")
    assert decision.status == "confirmed"
    assert decision.scoreable is True
    assert decision.candidate.physically_rooted is True
    assert chain_evidence.scoreable_root_ids == frozenset(item.root_observation_id for item in observations)

    target = tmp_path / "canonical-runtime.txt"
    target.write_text("network_download process_exec", encoding="utf-8")
    session = ArtifactEvidenceSession(
        artifact_read_snapshot=build_artifact_read_snapshot(target),
        static_program_analyses=(),
        yara_scan_result=unavailable_yara_scan_result("yara_disabled", status="disabled"),
    )
    snapshot = session.provisional_evidence(tag_evidence=tags, chain_evidence=chain_evidence)
    assert snapshot.chain_evidence.scoreable_root_ids == chain_evidence.scoreable_root_ids
