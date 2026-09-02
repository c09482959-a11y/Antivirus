from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_callbacks import (
    safe_stage_is_pre_execution,
    safe_start_wait_budget,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_numbers import (
    safe_record_float,
    safe_timeout_budget_number,
    timeout_budget_for_record,
)

RECOVERABLE = (RuntimeError, TypeError, ValueError, OSError, OverflowError)


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


def _record():
    return {"attempt": 2, "timeout_budget": {}}


def _suppressed(_where, _exc):
    return None


def test_stage1942_callback_failure_defaults_are_projected_without_fallback_routes():
    hostile_default = HostileValue()
    hostile_budget = HostileValue()
    failures = []

    budget = safe_start_wait_budget(
        start_wait_budget=lambda _record, _default: (_ for _ in ()).throw(RuntimeError("budget failed")),
        job_id="job-1",
        record=_record(),
        default_budget=hostile_budget,  # type: ignore[arg-type]
        reason="start_wait_failed",
        pid=11,
        failures=failures,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )

    assert budget == 0.0
    assert hostile_default.calls == []
    assert hostile_budget.calls == []
    assert [entry["reason"] for entry in failures] == ["start_wait_failed"]


def test_stage1942_stage_classifier_failure_uses_explicit_projection_not_sentinel_return():
    failures = []

    pre_execution = safe_stage_is_pre_execution(
        classifier=lambda _stage: (_ for _ in ()).throw(RuntimeError("classifier failed")),
        stage="queued",
        job_id="job-2",
        record=_record(),
        pid=22,
        failures=failures,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )

    assert pre_execution is False
    assert failures[0]["reason"] == "stage_pre_execution_classification_failed"
    assert failures[0]["checkpoint_must_record"] is True


def test_stage1942_policy_numbers_reject_hostile_values_without_hooks():
    hostile_record_value = HostileValue()
    hostile_budget_value = HostileValue()
    hostile_container = HostileValue()
    failures = []

    record_value = safe_record_float(
        record={"attempt": 3, "timeout_budget": {}, "running_at": hostile_record_value},
        field="running_at",
        default=4.0,
        job_id="job-3",
        pid=33,
        failures=failures,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )
    budget_value = safe_timeout_budget_number(
        record={"attempt": 4, "timeout_budget": {}},
        budget={"hard_timeout_sec": hostile_budget_value},
        field="hard_timeout_sec",
        default=5.0,
        job_id="job-4",
        pid=44,
        failures=failures,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )
    budget_evidence = timeout_budget_for_record({"timeout_budget": hostile_container})

    assert record_value == 4.0
    assert budget_value == 5.0
    assert hostile_record_value.calls == []
    assert hostile_budget_value.calls == []
    assert hostile_container.calls == []
    assert failures[0]["reason"] == "running_at_malformed"
    assert failures[1]["reason"] == "timeout_budget_hard_timeout_sec_malformed"
    assert budget_evidence["timeout_budget_unavailable_reason"] == "timeout_budget_container_malformed"
    assert budget_evidence["checkpoint_must_record"] is True


def test_stage1942_policy_callback_and_number_source_guards_block_regression():
    root = Path(__file__).resolve().parents[1]
    callback_source = (root / "scheduler" / "timeout" / "inmemory_timeout_policy_callbacks.py").read_text()
    numbers_source = (root / "scheduler" / "timeout" / "inmemory_timeout_policy_numbers.py").read_text()

    callback_forbidden = [
        "fallback",
        "return False",
        "return fallback",
    ]
    numbers_forbidden = [
        'reason=f"',
        'source=f"',
        "float(default)",
        "record.get(",
        "budget.get(",
    ]
    assert [(snippet) for snippet in callback_forbidden if snippet in callback_source] == []
    assert [(snippet) for snippet in numbers_forbidden if snippet in numbers_source] == []

    for file_name, source in {
        "inmemory_timeout_policy_callbacks.py": callback_source,
        "inmemory_timeout_policy_numbers.py": numbers_source,
    }.items():
        tree = ast.parse(source)
        raw_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                raw_calls.append((file_name, node.lineno, "f-string"))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"bool", "float", "int", "repr", "str", "vars"}:
                raw_calls.append((file_name, node.lineno, node.func.id))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                raw_calls.append((file_name, node.lineno, "get"))
        assert raw_calls == []

from Virus_Scan.scheduler.queue.inmemory_recovery_evidence_journal import InMemoryRecoveryEvidenceJournal
from Virus_Scan.scheduler.timeout.inmemory_timeout_retry_evidence import evidence_not_already_present


def test_stage1942_retry_evidence_index_fields_are_no_hook_projected():
    hostile_record = HostileValue()
    journal = InMemoryRecoveryEvidenceJournal()
    journal.append_retry((hostile_record,))

    projected = journal.retry_since(0)
    deduped = evidence_not_already_present(candidates=(hostile_record,), existing=())

    assert hostile_record.calls == []
    assert projected[0]["field_name"] == "retry_recovery_evidence[0]"
    assert projected[0]["reason"] == "recovery_evidence_record_rejected"
    assert deduped[0]["field_name"] == "candidate_evidence[0]"
    assert deduped[0]["reason"] == "candidate_evidence_record_rejected"


def test_stage1942_retry_evidence_source_guard_blocks_fstring_index_fields():
    root = Path(__file__).resolve().parents[1]
    sources = [
        (root / "scheduler" / "timeout" / "inmemory_timeout_retry_evidence.py").read_text(),
        (root / "scheduler" / "queue" / "inmemory_recovery_evidence_journal.py").read_text(),
    ]
    for source in sources:
        assert 'field_name=f"' not in source
        assert "candidate_evidence[{index}]" not in source
        tree = ast.parse(source)
        fstrings = [(node.lineno, "f-string") for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]
        assert fstrings == []

from Virus_Scan.scheduler.timeout.inmemory_timeout_settings import bounded_float_setting, timeout_env_value


def test_stage1942_timeout_settings_project_hostile_default_and_name_without_hooks():
    hostile_name = HostileValue()
    hostile_default = HostileValue()

    text, evidence = timeout_env_value({}, hostile_name, hostile_default)
    value, value_evidence = bounded_float_setting(
        {},
        name="UMIGE_INMEMORY_PROGRESS_STALE_SEC",
        default=hostile_default,  # type: ignore[arg-type]
        minimum=1.0,
    )

    assert "HostileValue" in text
    assert evidence == ()
    assert value == 1.0
    assert value_evidence
    assert hostile_name.calls == []
    assert hostile_default.calls == []


def test_stage1942_timeout_settings_source_guard_blocks_raw_default_conversions():
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "timeout" / "inmemory_timeout_settings.py").read_text()
    forbidden = [
        "str(default)",
        "float(value)",
        "float(minimum)",
        "dict.get(environ",
        "fallback_value=",
        "fallback=default",
    ]
    assert [(snippet) for snippet in forbidden if snippet in source] == []
