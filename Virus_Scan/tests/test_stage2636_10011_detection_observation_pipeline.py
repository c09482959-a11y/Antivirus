from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
    artifact_observations_for_tags,
)
from Virus_Scan.contracts.tag_evidence import scoreable_tag_evidence_records
from Virus_Scan.detection.chains.execution.event_materialization import tag_chain_events
from Virus_Scan.detection.enrichment.full_analysis.api_context import _build_api_enrichment_context
from Virus_Scan.detection.enrichment.full_analysis.input_stage import prepare_analysis_inputs
from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture


def _observation(tag: str, *, event_id: str, producer: str = "phase4_scanner") -> DetectionObservation:
    return DetectionObservation.create(
        tag=tag,
        producer_id=producer,
        stage_id="physical_scan",
        modality="static_structure",
        platform="windows",
        artifact_identity="sha256:artifact",
        target_identity="process:target",
        source_location=ObservationSourceLocation(
            "binary_offset", locator="sample.exe", byte_offset=16, event_id=event_id,
        ),
        timing_provenance="not_observed",
        integrity_status="verified",
        directness="direct",
        confidence=1.0,
    )


def test_one_physical_observation_projecting_three_tags_keeps_one_root() -> None:
    observations = artifact_observations_for_tags(
        ["process_target_opened", "remote_memory_written", "remote_thread_created"],
        producer_id="binary_micro_stage",
        stage_id="binary_structure",
        artifact_identity="sha256:one-artifact",
        source_location=ObservationSourceLocation(
            "binary_offset", locator="one.exe", byte_offset=64, byte_length=8,
        ),
        modality="static_structure",
        platform="windows",
        integrity_status="verified",
        directness="direct",
    )
    bundle = finalize_tag_evidence_generation(observations, path="one.exe", source="binary_micro_stage").evidence
    roots = {
        record.root_observation_id
        for record in bundle.records
        if record.canonical_tag_id in {
            "process_target_opened", "remote_memory_written", "remote_thread_created",
        }
    }
    assert len(roots) == 1


def test_two_independent_observations_of_same_tag_keep_distinct_roots() -> None:
    first = _observation("remote_memory_written", event_id="write-1")
    second = _observation("remote_memory_written", event_id="write-2")
    bundle = finalize_tag_evidence_generation([first, second], path="sample.exe", source="phase4_scanner").evidence
    roots = {
        record.root_observation_id
        for record in bundle.records
        if record.canonical_tag_id == "remote_memory_written"
        and record.evidence_kind in {"observed", "normalized"}
    }
    assert roots == {first.root_observation_id, second.root_observation_id}


def test_same_physical_source_across_producers_shares_root_not_observation_id() -> None:
    first = _observation("remote_memory_written", event_id="write-shared", producer="asset_scanner")
    second = _observation("remote_memory_written", event_id="write-shared", producer="analysis_scanner")
    assert first.observation_id != second.observation_id
    assert first.root_observation_id == second.root_observation_id


def test_duplicate_physical_projection_selection_is_input_order_independent() -> None:
    first = _observation("remote_memory_written", event_id="write-shared", producer="asset_scanner")
    second = _observation("remote_memory_written", event_id="write-shared", producer="analysis_scanner")
    forward = normalize_tag_evidence([first, second], derive=False)
    reverse = normalize_tag_evidence([second, first], derive=False)
    assert forward.to_record() == reverse.to_record()
    observed = next(record for record in forward.records if record.evidence_kind == "observed")
    assert observed.source_detector == "analysis_scanner"


def test_distinct_physical_locations_remain_distinct_across_producers() -> None:
    first = _observation("remote_memory_written", event_id="write-1", producer="asset_scanner")
    second = _observation("remote_memory_written", event_id="write-2", producer="analysis_scanner")
    assert first.root_observation_id != second.root_observation_id


def test_flat_string_input_is_publishable_but_never_scoreable() -> None:
    bundle = finalize_tag_evidence_generation(
        ["api_loadurl"], path="legacy.exe", strings_blob="api_loadurl", source="legacy_flat_scanner",
    ).evidence
    assert "api_loadurl" in bundle.tags
    assert scoreable_tag_evidence_records(bundle.records) == ()
    record = next(record for record in bundle.records if record.canonical_tag_id == "api_loadurl")
    assert record.modality == "unavailable"
    assert record.directness == "unavailable"
    assert record.unavailable_reason


def test_source_location_and_correlation_identity_survive_tag_to_chain_projection() -> None:
    observation = _observation("remote_thread_created", event_id="thread-7")
    bundle = finalize_tag_evidence_generation([observation], path="sample.exe", source="phase4_scanner").evidence
    events, failures = tag_chain_events(bundle)
    event = next(event for event in events if event.term == "remote_thread_created")
    assert failures == ()
    assert event.root_evidence_id == observation.root_observation_id
    assert event.target_identity == "process:target"
    assert event.artifact_identity == "sha256:artifact"
    assert event.platform == "windows"
    assert event.modality == "static_structure"
    assert event.source_location.event_id == "thread-7"
    assert event.source_location.byte_offset == 16


def test_api_enrichment_preserves_existing_producer_and_adds_api_producer() -> None:
    base = finalize_tag_evidence_generation(
        [_observation("process_target_opened", event_id="base", producer="binary_micro_stage")],
        path="sample.exe",
        source="binary_micro_stage",
    ).evidence

    def fake_enricher(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "api_calls": ["CreateRemoteThread"],
            "sequence": ["CreateRemoteThread"],
            "ngrams": [],
            "call_graph": {},
            "graph_features": {},
        }

    merged, _api_result, _timeline, _ordered = _build_api_enrichment_context(
        path="sample.exe",
        tags=base,
        strings_blob="CreateRemoteThread",
        strings_already_enriched=True,
        api_graph_enricher=fake_enricher,
        stage_failures=[],
    )
    producers = {record.source_detector for record in merged.records}
    assert "binary_micro_stage" in producers
    assert "api_call_classifier" in producers


def test_router_evidence_survives_full_analysis_input_without_producer_flattening(tmp_path: Path) -> None:
    sample = tmp_path / "producer-preservation.txt"
    sample.write_text("powershell -encodedcommand AAAA", encoding="utf-8")
    outcome = scan_file_by_type(str(sample), scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=artifact_read_snapshot_fixture(sample))
    assert outcome.tag_evidence.records
    route_producers = {record.source_detector for record in outcome.tag_evidence.records}
    facts = prepare_analysis_inputs(
        str(sample),
        tags=outcome.tag_evidence,
        curr_stage="text",
        strings_blob=sample.read_text(encoding="utf-8"),
        strings_already_enriched=True,
        artifact_read_snapshot=artifact_read_snapshot_fixture(sample),
        attack_repository_digest=scan_session_snapshot_fixture().cache_execution_identity.attack_repository_digest,
    )
    final_producers = {record.source_detector for record in facts.tag_evidence.records}
    assert route_producers <= final_producers
    assert "api" not in final_producers


def test_static_string_observation_is_not_relabelled_as_runtime_behavior() -> None:
    observation = DetectionObservation.create(
        tag="powershell_process_or_command_observed",
        producer_id="strings_scanner",
        stage_id="string_scan",
        modality="static_string",
        artifact_identity="sha256:artifact",
        source_location=ObservationSourceLocation("string_offset", locator="sample.ps1", byte_offset=3),
        timing_provenance="not_observed",
        integrity_status="verified",
        directness="direct",
        confidence=1.0,
    )
    bundle = finalize_tag_evidence_generation([observation], path="sample.ps1", source="strings_scanner").evidence
    record = next(record for record in bundle.records if record.canonical_tag_id == observation.tag)
    assert record.modality == "static_string"
    assert record.timing_provenance == "not_observed"


def test_observation_id_is_cross_process_deterministic() -> None:
    script = r"""
import json
from Virus_Scan.contracts.detection_observation import DetectionObservation, ObservationSourceLocation
value = DetectionObservation.create(
    tag='remote_memory_written', producer_id='scanner', stage_id='binary',
    modality='static_structure', platform='windows', artifact_identity='sha256:x',
    target_identity='process:1',
    source_location=ObservationSourceLocation('binary_offset', locator='x.exe', byte_offset=22),
    timing_provenance='not_observed', integrity_status='verified', directness='direct',
    confidence=1.0,
)
print(json.dumps([value.observation_id, value.root_observation_id]))
"""
    first = subprocess.check_output([sys.executable, "-c", script], text=True, timeout=30).strip()
    second = subprocess.check_output([sys.executable, "-c", script], text=True, timeout=30).strip()
    assert json.loads(first) == json.loads(second)
