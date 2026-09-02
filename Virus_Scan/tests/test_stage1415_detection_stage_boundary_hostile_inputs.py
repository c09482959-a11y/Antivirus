from __future__ import annotations
from Virus_Scan.detection.models.failure_state import DetectionRecoverableFailureRequest

from collections.abc import Mapping

from Virus_Scan.detection.models.evidence import StageCollectorMerge
from Virus_Scan.detection.models.input_stage_outputs import NormalizedFacts, RawScanFacts
from Virus_Scan.detection.models.stage_value_utils import freeze_detection_value, thaw_detection_value


class HostileText:
    def __str__(self):  # pragma: no cover - exercised by boundary safety
        raise RuntimeError("hostile str")

    def __repr__(self):  # pragma: no cover - exercised by boundary safety
        raise RuntimeError("hostile repr")


class HostileMapping(Mapping):
    def __iter__(self):
        raise RuntimeError("hostile iter")

    def __len__(self):
        return 1

    def __getitem__(self, key):
        raise RuntimeError("hostile getitem")

    def keys(self):
        raise RuntimeError("hostile keys")


def _flatten(value):
    if isinstance(value, Mapping):
        yielded = [value]
        for item in value.values():
            yielded.extend(_flatten(item))
        return yielded
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            out.extend(_flatten(item))
        return out
    return []


def test_stage1415_freeze_detection_value_records_hostile_mapping_evidence():
    frozen = freeze_detection_value(HostileMapping())
    thawed = thaw_detection_value(frozen)

    assert thawed["degraded"] is True
    assert thawed["unavailable_reason"] == "detection_mapping_keys_unavailable"
    assert thawed["final_json_must_record"] is True
    assert thawed["replay_record_required"] is True


def test_stage1415_raw_and_normalized_facts_record_hostile_identity_evidence():
    raw = RawScanFacts(
        path=HostileText(),
        tags=["process_injection", HostileText()],
        yara_hits=HostileMapping(),
        curr_stage=None,
        strings_blob="",
        strings_already_enriched=False,
    )
    normalized = NormalizedFacts(
        path=HostileText(),
        node=HostileText(),
        tags=HostileMapping(),
        yara_hits=[HostileText()],
        yara_evidence=HostileMapping(),
        curr_stage=HostileText(),
        strings_blob="",
        strings_already_enriched=False,
    )

    raw_reasons = [entry.get("unavailable_reason") for entry in _flatten(raw.failure_evidence)]
    normalized_reasons = [entry.get("unavailable_reason") for entry in _flatten(normalized.failure_evidence)]

    assert "raw_scan_path_unavailable" in raw_reasons
    assert any(tag == "process_injection" for tag in raw.tags)
    assert any(getattr(tag, "get", lambda *_: None)("unavailable_reason") == "detection_scalar_unavailable" for tag in raw.tags)
    assert "normalized_path_unavailable" in normalized_reasons
    assert "normalized_node_unavailable" in normalized_reasons
    assert "normalized_stage_unavailable" in normalized_reasons


def test_stage1415_stage_collector_merge_records_hostile_tags_and_metadata():
    merged = StageCollectorMerge(
        tags=("static_anchor", HostileText()),
        metadata={HostileText(): HostileText()},
        suspicious=True,
        errors=(HostileText(),),
    )

    tags, metadata, suspicious, errors = merged.as_tuple()
    assert "static_anchor" in tags
    assert suspicious is True
    assert any(isinstance(error, dict) and error.get("unavailable_reason") == "stage_collector_tag_unavailable" for error in errors)
    assert any(isinstance(error, dict) and error.get("unavailable_reason") == "stage_collector_error_unavailable" for error in errors)
    assert any(isinstance(key, str) and "detection_scalar_unavailable" in key for key in metadata)

from Virus_Scan.detection.models.failure_state import DetectionFailureState, failure_state_records


class HostileBool:
    def __bool__(self):  # pragma: no cover - exercised by boundary safety
        raise RuntimeError("hostile bool")

    def __str__(self):
        raise RuntimeError("hostile str")


def test_stage1415_detection_failure_state_records_hostile_fields_explicitly():
    recoverable = DetectionFailureState.from_recoverable_request(DetectionRecoverableFailureRequest(
        stage_name=HostileText(),
        error=HostileText(),
        error_source=HostileText(),
        affected_context=HostileText(),
        confidence_degraded=HostileBool(),
        json_record_required=HostileBool(),
        replay_record_required=HostileBool(),
    )).to_record()
    fatal = DetectionFailureState.fatal_failure(
        stage_name=HostileText(),
        error=HostileText(),
        error_source=HostileText(),
        affected_context=HostileText(),
    ).to_record()
    mapped = failure_state_records([HostileMapping()])
    unavailable_iter = failure_state_records(HostileMapping())

    assert recoverable["stage_name"] == "unknown"
    assert recoverable["error_source"] == "detection"
    assert recoverable["message"] == "detection_failure_message_unavailable"
    assert recoverable["json_record_required"] is True
    assert recoverable["replay_record_required"] is True
    assert fatal["state"] == "failed"
    assert mapped[0]["unavailable_reason"] == "detection_failure_mapping_unavailable"
    assert unavailable_iter[0]["unavailable_reason"] == "detection_failure_iterable_unavailable"
