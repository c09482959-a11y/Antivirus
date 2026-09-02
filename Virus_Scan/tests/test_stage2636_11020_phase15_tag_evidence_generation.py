from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
    artifact_observations_for_path_tags,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.tags.evidence_generation import (
    TAG_EVIDENCE_GENERATION_SCHEMA_VERSION,
    TagEvidenceGeneration,
    finalize_tag_evidence_generation,
    merge_tag_evidence_inputs,
)
from Virus_Scan.detection.tags.heuristics.finalization import (
    validate_tag_evidence_input_for_path,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence


def _observation(tag: str, event_id: str) -> DetectionObservation:
    return DetectionObservation.create(
        tag=tag,
        producer_id="phase15_scanner",
        stage_id="scanner_output",
        modality="static_structure",
        artifact_identity="sha256:" + "a" * 64,
        source_location=ObservationSourceLocation("event", event_id=event_id),
        integrity_status="verified",
        directness="direct",
        confidence=1.0,
    )


def test_phase15_generation_reuses_unchanged_input_without_refinalization() -> None:
    inputs = normalize_tag_evidence((_observation("powershell_exec", "one"),), derive=True)
    first = finalize_tag_evidence_generation(
        inputs, path="sample.ps1", strings_blob="powershell.exe", source="generation_zero",
    )
    repeated = finalize_tag_evidence_generation(
        inputs,
        path="sample.ps1",
        strings_blob="powershell.exe",
        source="redundant_downstream_stage",
        previous_generation=first,
    )

    assert repeated is first
    assert first.finalization_count == 1
    assert first.generation_index == 0
    assert first.parent_generation_id == ""
    assert first.to_record()["schema_version"] == TAG_EVIDENCE_GENERATION_SCHEMA_VERSION


def test_phase15_generation_appends_only_changed_validated_evidence() -> None:
    first_input = normalize_tag_evidence((_observation("powershell_exec", "one"),), derive=True)
    first = finalize_tag_evidence_generation(
        first_input, path="sample.ps1", strings_blob="powershell.exe", source="generation_zero",
    )
    addition = normalize_tag_evidence((_observation("static_network_send_operation", "two"),), derive=True)
    second = finalize_tag_evidence_generation(
        addition,
        path="sample.ps1",
        strings_blob="powershell.exe",
        source="generation_one",
        previous_generation=first,
    )

    assert type(second) is TagEvidenceGeneration
    assert second.generation_index == 1
    assert second.parent_generation_id == first.generation_id
    assert set(second.reused_evidence_ids) == {record.evidence_id for record in first.input_evidence.records}
    assert set(second.added_evidence_ids) == {record.evidence_id for record in addition.records}
    assert {"powershell_exec", "static_network_send_operation"} <= set(second.evidence.tags)
    assert {
        record.root_observation_id for record in second.input_evidence.records
    } == {
        first_input.records[0].root_observation_id,
        addition.records[0].root_observation_id,
    }


def test_phase15_input_merge_deduplicates_exact_evidence_ids_deterministically() -> None:
    evidence = normalize_tag_evidence((_observation("powershell_exec", "same"),), derive=True)
    merged = merge_tag_evidence_inputs((evidence, evidence, TagEvidence()))

    assert merged.records == evidence.records
    assert merged.tags == evidence.tags


def test_phase15_generation_validates_plain_tag_sequences_as_scanner_input() -> None:
    generation = finalize_tag_evidence_generation(
        ("router_stage_binary", "inmemory_raw_enrichment"),
        path="sample.bin",
        source="inmemory_raw",
    )

    assert "router_stage_binary" in generation.evidence.tags
    assert "inmemory_raw_enrichment" in generation.evidence.tags
    assert generation.finalization_count == 1


def test_phase15_stage_append_boundary_rejects_broad_scanner_conclusions() -> None:
    observations = artifact_observations_for_path_tags(
        ("memory_write", "thread_execution", "process_injection"),
        producer_id="broad_binary_scanner",
        stage_id="scanner_output",
        path="sample.bin",
        modality="static_structure",
    )
    validated = validate_tag_evidence_input_for_path(
        observations, path="sample.bin", source="broad_binary_scanner",
    )

    assert validated.tags == ()
    assert validated.records == ()


def test_phase15_reachable_stage_modules_do_not_call_primitive_finalizer_directly() -> None:
    repository = Path(__file__).resolve().parents[2]
    modules = (
        "Virus_Scan/routing/extension_scan_router.py",
        "Virus_Scan/routing/extension_scan_handlers.py",
        "Virus_Scan/detection/enrichment/full_analysis/input_stage.py",
        "Virus_Scan/detection/enrichment/full_analysis/api_context.py",
        "Virus_Scan/routing/asset_triage.py",
        "Virus_Scan/scanners/raw_queue_scan_result.py",
        "Virus_Scan/scheduler/workers/inmemory_raw_finalization_steps.py",
    )
    for relative in modules:
        source = (repository / relative).read_text(encoding="utf-8")
        assert "finalize_tag_evidence_for_path(" not in source
        assert "TagEvidence.from_records(" not in source


def test_phase15_public_contract_exposes_only_generation_finalization_owner() -> None:
    repository = Path(__file__).resolve().parents[2]
    public_source = (
        repository / "Virus_Scan/detection/api/public_contracts.py"
    ).read_text(encoding="utf-8")
    routing_source = (
        repository / "Virus_Scan/detection/api/routing_contracts.py"
    ).read_text(encoding="utf-8")
    tags_source = (
        repository / "Virus_Scan/detection/api/tags_contracts.py"
    ).read_text(encoding="utf-8")

    for source in (public_source, routing_source, tags_source):
        assert "finalize_tag_evidence_generation" in source
        assert "finalize_tags_for_path" not in source
        assert "finalize_tag_evidence_for_path" not in source


def test_phase15_primitive_policy_finalizer_is_private_to_generation_owner() -> None:
    repository = Path(__file__).resolve().parents[2]
    finalization_source = (
        repository / "Virus_Scan/detection/tags/heuristics/finalization.py"
    ).read_text(encoding="utf-8")
    generation_source = (
        repository / "Virus_Scan/detection/tags/evidence_generation.py"
    ).read_text(encoding="utf-8")

    assert "def _finalize_tag_evidence_for_path(" in finalization_source
    assert '"finalize_tag_evidence_for_path"' not in finalization_source
    assert "_finalize_tag_evidence_for_path(" in generation_source
