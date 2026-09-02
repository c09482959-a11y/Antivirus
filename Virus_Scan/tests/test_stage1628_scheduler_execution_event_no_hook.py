from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.scheduler.evidence.execution_events import (
    SchedulerExecutionEvent,
    SchedulerExecutionEventRequest,
    build_execution_event,
    build_raw_job_execution_event,
)


class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")


class HostileAttempt:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")


class HostileMetadata:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not read mapping")


class HostileJob:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")

    def get(self, _key, _default=None):
        type(self).touched += 1
        raise RuntimeError("do not call get")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not call items")


class HostileSequence:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")


def test_stage1628_execution_event_rejects_hostile_text_attempt_metadata_without_hooks():
    HostileText.touched = 0
    HostileAttempt.touched = 0
    HostileMetadata.touched = 0
    event = build_execution_event(SchedulerExecutionEventRequest(
        event_type=HostileText(),
        file_id=HostileText(),
        worker_id=HostileText(),
        attempt=HostileAttempt(),
        status=HostileText(),
        metadata=HostileMetadata(),
    ))

    assert HostileText.touched == 0
    assert HostileAttempt.touched == 0
    assert HostileMetadata.touched == 0
    payload = event.as_dict()
    assert payload["event_type"] == "scheduler_execution_event"
    assert payload["file_id"] is None
    assert payload["worker_id"] is None
    assert payload["attempt"] == 0
    assert payload["status"] == "unknown"
    assert payload["metadata"]["scheduler_mapping_unavailable"] is True
    rejected = payload["metadata"]["scheduler_execution_field_rejections"]
    assert rejected["event_type"]["scheduler_execution_field_rejected"] is True
    assert rejected["attempt"]["reason"] == "scheduler_execution_attempt_rejected"
    json.dumps(payload, sort_keys=True)


def test_stage1628_direct_execution_event_rejects_hostile_sequences_without_iterating():
    HostileSequence.touched = 0
    event = SchedulerExecutionEvent(
        event_type="direct",
        tags=HostileSequence(),
        errors=HostileSequence(),
    )

    assert HostileSequence.touched == 0
    payload = event.as_dict()
    assert payload["tags"][0]["unsupported_scheduler_value"] is True
    assert payload["errors"][0]["unsupported_scheduler_value"] is True
    json.dumps(payload, sort_keys=True)


def test_stage1628_raw_job_execution_event_rejects_non_owned_mapping_without_get_bool_or_iter():
    HostileJob.touched = 0
    HostileSequence.touched = 0
    event = build_raw_job_execution_event(HostileJob(), status="failed", worker_id="w1")

    assert HostileJob.touched == 0
    assert HostileSequence.touched == 0
    payload = event.as_dict()
    assert payload["event_type"] == "raw_job_execution"
    assert payload["metadata"]["raw_job_mapping_rejected"]["unsupported_scheduler_value"] is True
    assert payload["tags"] == []
    assert payload["errors"] == []
    json.dumps(payload, sort_keys=True)



def test_stage1827_execution_event_text_defaults_do_not_reintroduce_fallback_keyword_routes() -> None:
    evidence_root = Path(__file__).resolve().parents[1] / "scheduler" / "evidence"
    support_source = (evidence_root / "execution_event_support.py").read_text(encoding="utf-8")
    events_source = (evidence_root / "execution_events.py").read_text(encoding="utf-8")

    assert "fallback: str | None" not in support_source
    assert "return (None if allow_none else fallback)" not in support_source
    assert "fallback=\"scheduler_execution_event\"" not in events_source
    assert "fallback=None" not in events_source
    assert "fallback=\"unknown\"" not in events_source
