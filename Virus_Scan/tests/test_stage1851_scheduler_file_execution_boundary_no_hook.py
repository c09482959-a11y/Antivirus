from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scheduler.execution.scheduler_file_message_support import (
    safe_pipeline_worker_log_message,
    scheduler_slow_file_message,
)
from Virus_Scan.scheduler.execution.target_collection import _required_filesystem_path
from Virus_Scan.scheduler.execution.triage_escalation import should_escalate_after_triage


ROOT = Path(__file__).resolve().parents[1]
EXECUTION_ROOT = ROOT / "scheduler" / "execution"


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    getattribute_calls = 0

    def __getattribute__(self, name):
        if name == "__class__":
            type(self).getattribute_calls += 1
            raise AssertionError("__class__ hook must not execute")
        return object.__getattribute__(self, name)

    def __str__(self):
        type(self).str_calls += 1
        raise AssertionError("__str__ hook must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise AssertionError("__repr__ hook must not execute")

    def __format__(self, _spec):
        type(self).format_calls += 1
        raise AssertionError("__format__ hook must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise AssertionError("__bool__ hook must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise AssertionError("__iter__ hook must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise AssertionError("__float__ hook must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise AssertionError("__int__ hook must not execute")


class HostileError(Exception):
    str_calls = 0
    repr_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise AssertionError("exception __str__ hook must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise AssertionError("exception __repr__ hook must not execute")


def _reset_hooks() -> None:
    HostileValue.str_calls = 0
    HostileValue.repr_calls = 0
    HostileValue.format_calls = 0
    HostileValue.bool_calls = 0
    HostileValue.iter_calls = 0
    HostileValue.float_calls = 0
    HostileValue.int_calls = 0
    HostileValue.getattribute_calls = 0
    HostileError.str_calls = 0
    HostileError.repr_calls = 0


def _assert_no_hooks() -> None:
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.getattribute_calls == 0
    assert HostileError.str_calls == 0
    assert HostileError.repr_calls == 0


def test_stage1851_slow_file_message_preserves_exact_primitive_text() -> None:
    message = scheduler_slow_file_message(
        elapsed_file=1.234,
        path_text="/scan/root/sample.bin",
        basename=lambda path: Path(path).name,
    )

    assert message == "SLOW FILE: 1.23s sample.bin"


def test_stage1851_slow_file_message_rejects_hostile_scalars_without_hooks() -> None:
    _reset_hooks()
    hostile = HostileValue()
    message = scheduler_slow_file_message(
        elapsed_file=hostile,
        path_text="/scan/root/sample.bin",
        basename=lambda _path: hostile,
    )

    assert "SLOW FILE: unavailables" in message
    assert "scheduler_file_basename_rejected" in message
    _assert_no_hooks()


def test_stage1851_pipeline_worker_log_message_rejects_hostile_path_and_exception_without_hooks() -> None:
    _reset_hooks()
    hostile_path = HostileValue()
    hostile_error = HostileError("owned")

    message = safe_pipeline_worker_log_message(
        prefix="safe pipeline worker failed",
        path=hostile_path,
        exc=hostile_error,
    )

    assert message.startswith("safe pipeline worker failed for ")
    assert "unsupported_safe_pipeline_worker_path" in message
    assert "scheduler diagnostic detail unavailable without caller hooks" in message
    _assert_no_hooks()


def test_stage1851_required_target_path_error_uses_exact_owned_text_without_fstring_hooks() -> None:
    _reset_hooks()

    with pytest.raises(ValueError, match="scheduler_target_root:scheduler_path_rejected"):
        _required_filesystem_path(HostileValue(), field_name="scheduler_target_root")

    _assert_no_hooks()


def test_stage1851_triage_extension_failure_records_evidence_outside_exception_return_sentinel() -> None:
    calls = []

    def raise_extension(_path):
        raise RuntimeError("extension unavailable")

    result = should_escalate_after_triage(
        "sample.bin",
        (),
        False,
        {},
        "stage",
        get_scan_extension=raise_extension,
        deep_scan_thorough=lambda: False,
        contextual_dangerous_anchor_hits=lambda _hits: False,
        record_suppressed_failure=lambda where, exc: calls.append((where, type(exc).__name__)),
        recoverable_exceptions=(RuntimeError,),
    )

    assert result is True
    assert calls == [("scheduler_triage_extension_failed", "RuntimeError")]


def test_stage1851_current_scheduler_execution_sources_forbid_reopened_patterns() -> None:
    forbidden = {
        "scheduler_file_analysis.py": (
            'f"SLOW FILE: {elapsed_file:.2f}s {deps.basename(path_text)}"',
        ),
        "scheduler_file_terminal.py": (
            'f"SLOW FILE: {elapsed_file:.2f}s {deps.basename(path_text)}"',
        ),
        "scheduler_file_job.py": (
            'deps.log_error(f"safe pipeline worker timed out for {path}: {exc}")',
            'deps.log_error(f"safe pipeline worker failed for {path}: {exc}")',
        ),
        "target_collection.py": (
            'raise ValueError(f"{field_name}:{reason or \'scheduler_path_missing\'}")',
            'f"{scheduler_error_detail(e, max_length=500)}"',
        ),
    }
    for relative, snippets in forbidden.items():
        source = (EXECUTION_ROOT / relative).read_text(encoding="utf-8")
        for snippet in snippets:
            assert snippet not in source

    triage_source = (EXECUTION_ROOT / "triage_escalation.py").read_text(encoding="utf-8")
    extension_block = triage_source.split("try:\n        ext_value = get_scan_extension(path)", 1)[1]
    extension_handler = extension_block.split("if extension_failure_reason:", 1)[0]
    assert "return True" not in extension_handler
