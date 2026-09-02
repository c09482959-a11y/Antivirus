from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.evidence.execution_event_support import (
    field_issue,
    first_text_mapping_value,
    immutable_execution_mapping,
    immutable_execution_tuple,
    mapping_item_value,
    raw_job_items,
    scheduler_attempt_value,
    scheduler_bool_metadata_value,
    scheduler_text_value,
)


class HostileValue:
    touched = 0

    def __getattribute__(self, name: str):  # pragma: no cover - must not be invoked
        if name == "touched":
            return type.__getattribute__(type(self), "touched")
        type(self).touched += 1
        raise AssertionError(f"hostile __getattribute__ invoked for {name}")

    def __bool__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("hostile __bool__ invoked")

    def __str__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("hostile __str__ invoked")


class HostileKey:
    touched = 0

    def __eq__(self, other: object) -> bool:  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError(f"hostile __eq__ invoked for {other!r}")

    def __str__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("hostile __str__ invoked")


def test_stage2140_execution_event_support_has_no_local_any_surface() -> None:
    source = (Path(__file__).resolve().parents[1] / "scheduler" / "evidence" / "execution_event_support.py").read_text(
        encoding="utf-8"
    )

    assert "typing import Any" not in source
    assert "Any" not in source


def test_stage2140_execution_event_support_rejects_hostile_values_without_hooks() -> None:
    hostile = HostileValue()
    HostileValue.touched = 0

    text, text_issue = scheduler_text_value(hostile, field_name="name", default_text="fallback")
    attempt, attempt_issue = scheduler_attempt_value(hostile)
    bool_issue = scheduler_bool_metadata_value(hostile, field_name="fatal")
    tuple_issue = immutable_execution_tuple(hostile)
    issue = field_issue("payload", hostile, "payload_rejected")

    assert HostileValue.touched == 0
    assert text == "fallback"
    assert text_issue is not None
    assert text_issue["scheduler_execution_field_rejected"] is True
    assert attempt == 0
    assert attempt_issue is not None
    assert attempt_issue["reason"] == "scheduler_execution_attempt_rejected"
    assert bool_issue["unsupported_scheduler_value"] is True
    assert tuple_issue[0]["unsupported_scheduler_value"] is True
    assert issue["value_type"] == "HostileValue"


def test_stage2140_execution_event_mapping_helpers_do_not_call_hostile_key_equality() -> None:
    HostileKey.touched = 0
    items = ((HostileKey(), "bad"), ("path", "sample.bin"))

    assert mapping_item_value(items, "path") == "sample.bin"
    assert first_text_mapping_value(items, "path") == "sample.bin"
    assert mapping_item_value(items, "missing", "fallback") == "fallback"
    assert HostileKey.touched == 0


def test_stage2140_execution_event_absence_and_mapping_domains_remain_replayable() -> None:
    assert raw_job_items(HostileValue()) is None
    assert immutable_execution_mapping(None) == immutable_execution_mapping({})
    assert scheduler_text_value(None, field_name="file_id", default_text=None, allow_none=True) == (None, None)
    assert scheduler_attempt_value(None) == (0, None)
    assert scheduler_bool_metadata_value(None, field_name="retried") is False
