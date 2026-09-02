"""Phase 12: one official ATT&CK evaluation owner after final evidence freeze."""
from __future__ import annotations

from pathlib import Path
from Virus_Scan.contracts.artifact_evidence_snapshot import ArtifactEvidenceSnapshot
from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.yara_hits import unavailable_yara_scan_result
from Virus_Scan.detection.attack.evaluation_stage import (
    evaluate_final_attack_mapping,
    unavailable_attack_mapping_result,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.runtime.api import (
    ResourceLockSet,
    configure_mitre_runtime,
    release_mitre_runtime,
)
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import (
    attack_contract_repository,
)
from Virus_Scan.detection.registries.chain_registry import (
    CHAIN_REGISTRY_DIGEST,
    CHAIN_REGISTRY_VERSION,
)
from Virus_Scan.detection.scoring.adaptive.evidence_projection_components import (
    mitre_probability_component,
)


def _final_evidence(tmp_path: Path) -> ArtifactEvidenceSnapshot:
    target = tmp_path / "phase12.bin"
    target.write_bytes(b"phase12-attack-evaluation\n")
    return ArtifactEvidenceSnapshot(
        artifact_read_snapshot=build_artifact_read_snapshot(target),
        physical_observations=(),
        static_program_analyses=(),
        yara_scan_result=unavailable_yara_scan_result("yara_disabled", status="disabled"),
        tag_evidence=TagEvidence(),
        chain_evidence=ChainEvidence(CHAIN_REGISTRY_VERSION, CHAIN_REGISTRY_DIGEST),
        parser_analysis_limitations=(),
        evidence_completeness="complete",
    )


def test_phase12_evaluation_stage_consumes_final_snapshot_once(tmp_path: Path) -> None:
    final = _final_evidence(tmp_path)
    repository = attack_contract_repository()
    lock_set = ResourceLockSet()
    lock_set.acquire(tmp_path / "phase12-mitre-runtime.lock", writable=True)
    configure_mitre_runtime(
        repository,
        enabled=True,
        status={"unavailable_reason": ""},
        lock_set=lock_set,
    )
    try:
        result = evaluate_final_attack_mapping(final)
    finally:
        release_mitre_runtime()

    assert result.ready is True
    assert result.repository_digest == repository.digest
    source = Path(
        "Virus_Scan/detection/attack/evaluation_stage.py"
    ).read_text(encoding="utf-8")
    assert source.count("map_attack_evidence(") == 1
    assert "map_attack_evidence(runtime.repository, evidence)" in source
    assert "evidence.tag_evidence" not in source
    assert "evidence.chain_evidence" not in source


def test_phase12_probability_component_is_pure_mapping_projection() -> None:
    result = unavailable_attack_mapping_result("mitre_disabled")
    probability, reason, evidence = mitre_probability_component(result)

    assert probability == 0.0
    assert reason == "mitre_official_mapping_unavailable"
    assert evidence["ready"] is False
    assert evidence["unavailable_reason"] == "mitre_disabled"


def test_phase12_pipeline_freezes_then_maps_once_then_scores() -> None:
    source = Path("Virus_Scan/detection/orchestration/full_analysis/pipeline.py").read_text(encoding="utf-8")
    freeze_index = source.index("build_artifact_evidence_lifecycle(")
    mapping_index = source.index("deps.evaluate_final_attack_mapping(")
    scoring_index = source.index("score_full_analysis_context(", mapping_index)

    assert freeze_index < mapping_index < scoring_index
    assert source.count("deps.evaluate_final_attack_mapping(") == 1
    assert "evidence_lifecycle.final_evidence" in source[mapping_index:scoring_index]


def test_phase12_repository_has_one_production_mapper_execution_owner() -> None:
    production_root = Path("Virus_Scan")
    call_sites: list[str] = []
    for path in production_root.rglob("*.py"):
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if "map_attack_evidence(" in text and path.name != "mapper.py":
            call_sites.append(path.as_posix())
        assert "map_current_attack_evidence" not in text

    assert call_sites == ["Virus_Scan/detection/attack/evaluation_stage.py"]

    scoring = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("Virus_Scan/detection/scoring").rglob("*.py")
    )
    assert "map_attack_evidence(" not in scoring
    assert "map_current_attack_evidence" not in scoring


def test_phase12_result_and_adaptive_projection_receive_mapping_result_directly() -> None:
    pipeline_execution = Path(
        "Virus_Scan/detection/orchestration/full_analysis/pipeline_execution.py"
    ).read_text(encoding="utf-8")
    score_input = Path(
        "Virus_Scan/detection/scoring/full_analysis/input_builder.py"
    ).read_text(encoding="utf-8")
    adaptive = Path(
        "Virus_Scan/detection/scoring/adaptive/evidence_projection.py"
    ).read_text(encoding="utf-8")
    result_stage = Path(
        "Virus_Scan/detection/evidence/full_analysis/result_stage.py"
    ).read_text(encoding="utf-8")

    assert "attack_mapping_result=attack_mapping_result" in pipeline_execution
    assert "attack_mapping_result=request.attack_mapping_result" in score_input
    assert "attack_mapping_result: AttackMappingResult" in adaptive
    assert "official_attack_probability_evidence(\n        attack_mapping_result\n    )" in result_stage
