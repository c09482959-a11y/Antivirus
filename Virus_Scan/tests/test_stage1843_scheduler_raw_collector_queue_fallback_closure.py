"""Stage 1843: raw collector/raw queue fallback and f-string closure."""

from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.evidence.raw_collector_context import raw_collector_context_failure
from Virus_Scan.scheduler.evidence.raw_queue_failure import default_failure_info
from Virus_Scan.scheduler.evidence.raw_queue_issue import record_raw_queue_issue


class HostileValue:
    touched = 0

    def __str__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned string hook must not execute")

    def __repr__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned repr hook must not execute")

    def __int__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned int hook must not execute")


def test_stage1843_raw_collector_context_uses_owned_field_names_without_hooks() -> None:
    HostileValue.touched = 0
    calls: list[tuple[str, dict[str, object]]] = []
    degraded_inputs: list[list[object]] = []

    def report(stage, exc, *, fatal, extra):
        calls.append((stage, extra))

    def degraded(tags):
        degraded_inputs.append(list(tags))
        return list(tags)

    result = raw_collector_context_failure(
        (HostileValue(),),
        HostileValue(),
        RuntimeError("boom"),
        path=HostileValue(),
        start=HostileValue(),
        report=report,
        scanner_degraded_tags=degraded,
    )

    assert result == ["raw_context_scan_failed"]
    assert degraded_inputs == [["raw_context_scan_failed"]]
    assert calls[0][0] == "raw_raw_collector_context_scan_failed"
    extra = calls[0][1]
    assert extra["collector_evidence"]["field_name"] == "raw_context_text"
    assert extra["path_evidence"]["field_name"] == "raw_context_path"
    assert extra["start_evidence"]["field_name"] == "raw_context_start"
    unsupported = extra["tags_evidence"]["unsupported_values"]
    assert unsupported[0]["field_name"] == "raw_context_tag_0"
    assert HostileValue.touched == 0


def test_stage1843_raw_queue_failure_and_issue_keep_stable_extra_keys_without_fstring_hooks() -> None:
    HostileValue.touched = 0
    hostile_key = HostileValue()
    info = default_failure_info(
        stage=HostileValue(),
        error=HostileValue(),
        exception_type=HostileValue(),
        worker_pid=HostileValue(),
        attempt=HostileValue(),
        extra={hostile_key: HostileValue()},
    )

    assert info["stage"] == "queue_failed"
    assert info["exception_type"] == "HostileValue"
    assert info["unsupported_extra_key_0"]["field_name"] == "unsupported_extra_key_0"

    calls: list[tuple[str, dict[str, object]]] = []
    record_raw_queue_issue(
        HostileValue(),
        RuntimeError("boom"),
        extra={hostile_key: HostileValue()},
        record_scheduler_suppressed=lambda marker, exc, *, extra=None: calls.append((marker, extra)),
        record_raw_suppressed=lambda marker, exc: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError),
    )

    assert calls[0][0] == "raw_queue_issue"
    assert calls[0][1]["unsupported_extra_key_0"]["field_name"] == "unsupported_extra_key_0"
    assert HostileValue.touched == 0


def test_stage1843_sources_remove_repaired_raw_queue_fallback_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    source = "\n".join(
        (root / relative).read_text(encoding="utf-8")
        for relative in (
            "scheduler/evidence/raw_collector_context.py",
            "scheduler/evidence/raw_queue_failure.py",
            "scheduler/evidence/raw_queue_issue.py",
        )
    )
    forbidden = (
        "def _exact_text(value: object, *, fallback: str)",
        "return fallback, None",
        "return fallback, unsupported_scheduler_value_evidence",
        'field_name=f"raw_context_tag_{index}"',
        '_exact_text(collector, fallback="raw_collector")',
        'default=f"unsupported_extra_key_{index}"',
        "default=no_hook_type_name(exception_type)",
        'out[f"unsupported_extra_key_{index}"]',
    )
    for snippet in forbidden:
        assert snippet not in source
