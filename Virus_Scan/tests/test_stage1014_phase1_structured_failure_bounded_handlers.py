from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.runtime import structured_failures


def test_stage1014_structured_failure_recorder_uses_named_bounded_handlers() -> None:
    source_path = Path("Virus_Scan/runtime/structured_failures.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=source_path.as_posix())

    offenders: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            caught = "bare" if node.type is None else ast.unparse(node.type)
            if caught in {"bare", "Exception", "BaseException"}:
                offenders.append((node.lineno, caught))

    assert offenders == []


def test_stage1014_trace_tail_failure_remains_explicit_after_bounded_handler() -> None:
    structured_failures.clear_failure_records()

    def _broken_format_exception(*args, **kwargs):
        raise RuntimeError("trace formatting unavailable")

    try:
        raise ValueError("boom")
    except ValueError as exc:
        record = structured_failures.record_failure(
            "runtime",
            "trace_tail_boundary",
            exc,
            trace_formatter=_broken_format_exception,
        )

    assert record.trace_tail == "trace_unavailable:RuntimeError"
    assert any("failure_trace_tail:RuntimeError" in item for item in structured_failures.failure_recorder_internal_errors())


def test_stage1014_callback_failures_remain_visible_without_baseexception_handler() -> None:
    structured_failures.clear_failure_records()

    class BrokenTelemetry:
        def event(self, *args, **kwargs):
            raise RuntimeError("telemetry unavailable")

    record = structured_failures.record_failure(
        "runtime",
        "telemetry_boundary",
        RuntimeError("primary failure"),
        telemetry=BrokenTelemetry(),
    )

    assert record.error_type == "RuntimeError"
    assert any("failure_telemetry:RuntimeError" in item for item in structured_failures.failure_recorder_internal_errors())
