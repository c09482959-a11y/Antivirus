from __future__ import annotations

from Virus_Scan.detection.contracts.string_extraction import (
    build_extraction_view,
    looks_like_base64_payload,
    normalize_obfuscated_text,
    observed_decoded_payload_texts,
)
from Virus_Scan.detection.correlation.temporal.behavior_timeline import build_behavior_timeline
from Virus_Scan.detection.correlation.temporal.ordered_events import iter_ordered_string_events


class HostileStringBoundary:
    str_touched = 0
    repr_touched = 0
    bool_touched = 0
    iter_touched = 0
    dict_touched = 0

    def __str__(self):  # pragma: no cover - regression guard
        type(self).str_touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):  # pragma: no cover - regression guard
        type(self).repr_touched += 1
        raise RuntimeError("do not repr")

    def __bool__(self):  # pragma: no cover - regression guard
        type(self).bool_touched += 1
        raise RuntimeError("do not truth-test")

    def __iter__(self):  # pragma: no cover - regression guard
        type(self).iter_touched += 1
        raise RuntimeError("do not iterate")

    @property
    def __dict__(self):  # pragma: no cover - regression guard
        type(self).dict_touched += 1
        raise RuntimeError("do not inspect dict")


def _reset_hostile() -> None:
    HostileStringBoundary.str_touched = 0
    HostileStringBoundary.repr_touched = 0
    HostileStringBoundary.bool_touched = 0
    HostileStringBoundary.iter_touched = 0
    HostileStringBoundary.dict_touched = 0


def _assert_no_hooks() -> None:
    assert HostileStringBoundary.str_touched == 0
    assert HostileStringBoundary.repr_touched == 0
    assert HostileStringBoundary.bool_touched == 0
    assert HostileStringBoundary.iter_touched == 0
    assert HostileStringBoundary.dict_touched == 0


def test_stage1601_detection_string_extraction_rejects_hostile_text_without_hooks() -> None:
    _reset_hostile()
    hostile = HostileStringBoundary()

    assert looks_like_base64_payload(hostile) is False
    assert normalize_obfuscated_text(hostile) == "string_extraction_failure_evidence"
    view = build_extraction_view(hostile, path=hostile, decoded_payloads=[{"text": hostile}])

    assert "string_extraction_failure_evidence" in view
    _assert_no_hooks()


def test_stage1601_observed_decoded_payloads_reject_unknown_records_without_hooks() -> None:
    _reset_hostile()
    hostile = HostileStringBoundary()

    observed = observed_decoded_payload_texts([hostile])

    assert observed == ("decoded_payload_observation_unavailable",)
    _assert_no_hooks()


def test_stage1601_temporal_ordered_string_events_reject_hostile_blob_without_hooks() -> None:
    _reset_hostile()
    hostile = HostileStringBoundary()

    assert list(iter_ordered_string_events(hostile)) == []

    _assert_no_hooks()


def test_stage1601_behavior_timeline_records_rejected_inputs_without_hooks() -> None:
    _reset_hostile()
    hostile = HostileStringBoundary()

    timeline, ordered = build_behavior_timeline(
        hostile,
        api_calls=hostile,
        api_sequence=hostile,
        tags=hostile,
        decoded_payloads=[{"text": hostile}],
    )

    assert any(event.get("kind") == "failure_evidence" for event in timeline)
    assert "api_timeline_failure_evidence" in ordered
    _assert_no_hooks()

from Virus_Scan.detection.contracts.progress import stage_progress


class HostileProgressScalar:
    str_touched = 0
    int_touched = 0

    def __str__(self):  # pragma: no cover - regression guard
        type(self).str_touched += 1
        raise RuntimeError("do not stringify progress")

    def __int__(self):  # pragma: no cover - regression guard
        type(self).int_touched += 1
        raise RuntimeError("do not int progress")


def test_stage1601_progress_rejects_hostile_stage_and_counts_without_hooks() -> None:
    HostileProgressScalar.str_touched = 0
    HostileProgressScalar.int_touched = 0
    hostile = HostileProgressScalar()

    progress = stage_progress(hostile, inc=hostile, bytes_delta=hostile)

    assert progress["stage"] == "scan"
    assert progress["inc"] == 0
    assert progress["bytes_delta"] == 0
    assert HostileProgressScalar.str_touched == 0
    assert HostileProgressScalar.int_touched == 0

from Virus_Scan.detection.correlation.temporal.timeline import (
    _timeline_count,
    real_ordered_event_names,
    real_timeline_events,
    timeline_transitions,
)


class HostileTimelineValue:
    str_touched = 0
    bool_touched = 0
    iter_touched = 0
    float_touched = 0

    def __str__(self):  # pragma: no cover - regression guard
        type(self).str_touched += 1
        raise RuntimeError("do not stringify timeline value")

    def __bool__(self):  # pragma: no cover - regression guard
        type(self).bool_touched += 1
        raise RuntimeError("do not truth-test timeline value")

    def __iter__(self):  # pragma: no cover - regression guard
        type(self).iter_touched += 1
        raise RuntimeError("do not iterate timeline value")

    def __float__(self):  # pragma: no cover - regression guard
        type(self).float_touched += 1
        raise RuntimeError("do not float timeline value")


def _reset_timeline_hostile() -> None:
    HostileTimelineValue.str_touched = 0
    HostileTimelineValue.bool_touched = 0
    HostileTimelineValue.iter_touched = 0
    HostileTimelineValue.float_touched = 0


def _assert_timeline_no_hooks() -> None:
    assert HostileTimelineValue.str_touched == 0
    assert HostileTimelineValue.bool_touched == 0
    assert HostileTimelineValue.iter_touched == 0
    assert HostileTimelineValue.float_touched == 0


def test_stage1601_timeline_event_helpers_reject_unknown_iterables_without_hooks() -> None:
    _reset_timeline_hostile()
    hostile = HostileTimelineValue()

    assert real_ordered_event_names(hostile) == []
    assert real_timeline_events(hostile) == []
    assert timeline_transitions(hostile) == ([], [], [], [])

    _assert_timeline_no_hooks()


def test_stage1601_timeline_count_rejects_hostile_numeric_without_hooks() -> None:
    _reset_timeline_hostile()
    hostile = HostileTimelineValue()

    assert _timeline_count(hostile) is None

    _assert_timeline_no_hooks()
