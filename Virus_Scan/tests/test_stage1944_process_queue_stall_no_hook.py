from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

from Virus_Scan.scheduler.timeout.process_queue_stall_evidence import stall_escalation_evidence
from Virus_Scan.scheduler.timeout.process_queue_stall_reporting import (
    pid_for_process,
    record_stall_issue,
    termination_result_snapshot,
)


class HostileValue:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _hit(self, name: str):
        self.calls.append(name)
        raise AssertionError(name)

    def __bool__(self):
        return self._hit("__bool__")

    def __float__(self):
        return self._hit("__float__")

    def __format__(self, _spec):
        return self._hit("__format__")

    def __int__(self):
        return self._hit("__int__")

    def __iter__(self) -> Iterator[object]:
        return self._hit("__iter__")

    def __repr__(self):
        return self._hit("__repr__")

    def __str__(self):
        return self._hit("__str__")


class HostileProc:
    def __init__(self) -> None:
        self.calls: list[str] = []

    @property
    def pid(self):
        self.calls.append("pid")
        raise AssertionError("pid")


class HostileResult:
    def __init__(self) -> None:
        self.calls: list[str] = []

    @property
    def pid(self):
        self.calls.append("pid")
        raise AssertionError("pid")

    @property
    def error(self):
        self.calls.append("error")
        raise AssertionError("error")


def test_stage1944_stall_evidence_reason_fields_are_projected_without_fstrings_or_hooks():
    hostile = HostileValue()
    evidence = stall_escalation_evidence(
        worker_idx=hostile,
        pid=hostile,
        action=hostile,  # type: ignore[arg-type]
        reason=hostile,  # type: ignore[arg-type]
        error=hostile,  # type: ignore[arg-type]
        source=hostile,  # type: ignore[arg-type]
        elapsed_sec=hostile,  # type: ignore[arg-type]
    ).as_record()

    assert hostile.calls == []
    assert evidence["scheduler_stall_evidence_materialization_failed"] is True
    assert "stall_worker_idx" in evidence["worker_idx"]["field_name"]
    assert "stall_action_rejected" in evidence["stall_evidence_materialization_rejections"]


def test_stage1944_stall_reporting_rejects_public_properties_and_hostile_issue_action_without_hooks():
    proc = HostileProc()
    result = HostileResult()
    action = HostileValue()
    records: list[dict[str, object]] = []

    pid = pid_for_process(proc)
    snapshot = termination_result_snapshot(result, replacement_pid=pid)

    def record_issue(*_args, **_kwargs):
        raise RuntimeError("issue recorder failed")

    record_stall_issue(
        record_issue=record_issue,
        evidence_records=records,
        stage="process_queue_stall_worker_terminate_failed",
        error=RuntimeError("terminate failed"),
        extra={"termination": snapshot},
        worker_idx=HostileValue(),
        pid=pid,
        action=action,  # type: ignore[arg-type]
        elapsed_sec=HostileValue(),  # type: ignore[arg-type]
    )

    assert proc.calls == []
    assert result.calls == []
    assert action.calls == []
    assert pid["unsupported_scheduler_value"] is True
    assert records[0]["action"] == "stall_issue_recording"
    assert records[0]["final_json_must_record"] is True


def test_stage1944_process_queue_stall_source_guards_block_legacy_fallback_and_hook_formatting():
    root = Path(__file__).resolve().parents[1]
    files = [
        "scheduler/timeout/process_queue_stall_evidence.py",
        "scheduler/timeout/process_queue_stall_reporting.py",
    ]
    forbidden_text = [
        'f"{field_name}',
        'reason=f"',
        'field_name}_rejected',
        'fallback=',
        'fallback_pid',
        'dict.get(',
        'class_dict.get(',
        'action=f"{action}_issue_recording"',
    ]
    text_violations = []
    ast_violations = []
    for file_name in files:
        source = (root / file_name).read_text()
        for snippet in forbidden_text:
            if snippet in source:
                text_violations.append((file_name, snippet))
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                ast_violations.append((file_name, node.lineno, "f-string"))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                ast_violations.append((file_name, node.lineno, "get"))
    assert text_violations == []
    assert ast_violations == []
