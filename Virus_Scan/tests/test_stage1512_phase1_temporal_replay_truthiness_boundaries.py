"""Stage 1512 temporal/replay no-hook boundary regressions."""
from __future__ import annotations

from Virus_Scan.models.replay.api import result_learning_payload
from Virus_Scan.models.replay.payload import safe_parent_replay_result_for_normalization
from Virus_Scan.models.temporal import anomaly as temporal_anomaly
from Virus_Scan.models.temporal import validation as temporal_validation


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.bool_calls = 0
        return obj

    def __str__(self):
        return self

    def strip(self, *args, **kwargs):
        return self

    def __bool__(self):
        self.bool_calls += 1
        raise AssertionError("caller-owned temporal/replay text truthiness was probed")


def test_stage1512_temporal_validation_does_not_truth_test_stage_text():
    prev = HostileText("archive")
    curr = HostileText("runtime")

    evidence = temporal_validation.compute_temporal_validation(
        "node:stage1512", tags=("network_download",),
        prev_stage=prev, curr_stage=curr,
    )

    assert evidence["evidence_type"] == "temporal_validation"
    assert prev.bool_calls == 0
    assert curr.bool_calls == 0


def test_stage1512_temporal_anomaly_stage_sequence_uses_detached_stage_text_without_hooks():
    prev = HostileText("archive")
    curr = HostileText("runtime")

    score = temporal_anomaly.temporal_stage_sequence_anomaly(
        prev, ("decode",), curr, ("exec",),
    )

    assert 0.0 <= score <= 1.0
    assert prev.bool_calls == 0
    assert curr.bool_calls == 0


def test_stage1512_temporal_flat_events_materializes_hostile_stage_text():
    stage = HostileText("asset")

    events = temporal_anomaly.temporal_flat_events(
        ({"time": 1.0, "stage": stage, "tags": ("download",)},)
    )

    assert events[0].stage == "asset"
    assert events[0].behavior_id == "download"
    assert events[0].timestamp_kind == "observed"
    assert stage.bool_calls == 0


def test_stage1512_replay_normalization_does_not_truth_test_safe_text_fields():
    file_name = HostileText("sample.py")

    normalized, resolved = safe_parent_replay_result_for_normalization(
        {"file": file_name, "classification": "benign", "tags": ["normal_tag"]}
    )

    assert normalized["file"] == "sample.py"
    assert resolved == "sample.py"
    assert file_name.bool_calls == 0


def test_stage1512_replay_payload_does_not_truth_test_stage_fallback_text():
    current = HostileText("script")
    previous = HostileText("archive")

    payload = result_learning_payload({
        "file": "sample.py", "classification": "benign", "score": 1.0,
        "tags": ["normal_tag"], "engine_context": {"other": 1.0},
        "scan_integrity": {"allow_learning": True},
        "effective_stage": current, "previous_stage": previous,
    })

    assert payload is not None
    assert payload["curr_stage"] == "script"
    assert payload["prev_stage"] == "archive"
    assert current.bool_calls == 0
    assert previous.bool_calls == 0
