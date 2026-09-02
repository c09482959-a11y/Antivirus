from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

from Virus_Scan.scheduler.queue.retry_integrity_persistence import (
    RetryIntegrityPersistenceFailureRequest,
    record_retry_integrity_persistence_failure,
)
from Virus_Scan.scheduler.queue.retry_log_publication import safe_report_retry_log_failure
from Virus_Scan.scheduler.queue.retry_policy import (
    RetryPolicyRequest,
    run_file_with_retry,
)


class _HookBomb:
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


class _HostileMapping:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _hit(self, name: str):
        self.calls.append(name)
        raise AssertionError(name)

    def get(self, _key, _default=None):
        return self._hit("get")

    def items(self):
        return self._hit("items")

    def keys(self):
        return self._hit("keys")

    def values(self):
        return self._hit("values")

    def __iter__(self):
        return self._hit("__iter__")

    def __len__(self):
        return self._hit("__len__")

    def __getitem__(self, _key):
        return self._hit("__getitem__")


def _clear_integrity(_path):
    return None


def _set_integrity(_path, _integrity):
    return None


def _report_retry_log_failure(_error, _context):
    return None


def test_stage1791_retry_max_return_rejects_hostile_scalar_without_hooks():
    hostile = _HookBomb()

    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        {},
        False,
        worker_once=lambda path, _prev, _timeout: (path, {"ok": True}),
        retry_max=lambda _prev: hostile,
        is_retryable_failure=lambda _value: False,
        clear_integrity=_clear_integrity,
        get_integrity=lambda _path: {},
        set_integrity=_set_integrity,
        report_retry_log_failure=_report_retry_log_failure,
    ))

    assert hostile.calls == []
    evidence = result["scan_integrity"]["file_retry_failures"][0]
    assert evidence["callback_name"] == "retry_max"
    assert evidence["final_json_must_record"] is True


def test_stage1791_retry_classifier_return_rejects_hostile_truthiness_without_hooks():
    hostile = _HookBomb()

    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        {},
        False,
        worker_once=lambda path, _prev, _timeout: (path, {"error": "transient"}),
        retry_max=lambda _prev: 1,
        is_retryable_failure=lambda _value: hostile,
        clear_integrity=_clear_integrity,
        get_integrity=lambda _path: {},
        set_integrity=_set_integrity,
        report_retry_log_failure=_report_retry_log_failure,
    ))

    assert hostile.calls == []
    evidence = [
        item
        for item in result["scan_integrity"]["file_retry_failures"]
        if item["callback_name"] == "is_retryable_failure"
    ]
    assert evidence
    assert evidence[0]["checkpoint_must_record"] is True


def test_stage1791_worker_result_hostile_mapping_becomes_schema_evidence_without_hooks():
    hostile = _HostileMapping()

    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        {},
        False,
        worker_once=lambda path, _prev, _timeout: (path, hostile),
        retry_max=lambda _prev: 0,
        is_retryable_failure=lambda _value: False,
        clear_integrity=_clear_integrity,
        get_integrity=lambda _path: {},
        set_integrity=_set_integrity,
        report_retry_log_failure=_report_retry_log_failure,
    ))

    assert hostile.calls == []
    assert result["result_unavailable"] is True
    assert result["scan_integrity"]["queue_retry_policy_callback_failed"] is True


def test_stage1791_retry_publication_attempt_rejects_hostile_int_without_hooks():
    hostile = _HookBomb()
    contexts = []

    safe_report_retry_log_failure(
        retry_failures=[],
        path="sample.bin",
        attempt=hostile,
        original_error=RuntimeError("publish failed"),
        report_retry_log_failure=lambda error, context: contexts.append((error, context)),
    )

    assert hostile.calls == []
    assert contexts[0][1]["attempt"] == 0
    assert isinstance(contexts[0][0], ValueError)


def test_stage1791_retry_integrity_report_attempt_rejects_hostile_int_without_hooks():
    hostile = _HookBomb()
    contexts = []
    integrity: dict[str, object] = {}
    result: dict[str, object] = {}

    record_retry_integrity_persistence_failure(RetryIntegrityPersistenceFailureRequest(
        result=result,
        integrity=integrity,
        path="sample.bin",
        attempt=hostile,
        error=RuntimeError("persist failed"),
        report_retry_log_failure=lambda error, context: contexts.append((error, context)),
    ))

    assert hostile.calls == []
    assert contexts[0][1]["attempt"] == 0
    assert result["queue_retry_integrity_persistence_failed"] is True


def test_stage1791_retry_architecture_blocks_raw_conversion_and_mapping_hooks():
    root = Path(__file__).resolve().parents[1]
    files = [
        root / "scheduler" / "queue" / "retry_policy_callback_safety.py",
        root / "scheduler" / "queue" / "retry_worker_contract.py",
        root / "scheduler" / "queue" / "retry_log_publication.py",
        root / "scheduler" / "queue" / "retry_integrity_persistence.py",
    ]
    forbidden_names = {"bool", "dict", "float", "int", "repr", "str", "vars"}
    forbidden_attrs = {"get", "items", "keys", "values"}
    violations: list[tuple[str, int, str]] = []
    for file in files:
        tree = ast.parse(file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in forbidden_names:
                violations.append((file.name, node.lineno, node.func.id))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_attrs:
                allowed_dict_get = (
                    node.func.attr == "get"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "dict"
                )
                if not allowed_dict_get:
                    violations.append((file.name, node.lineno, node.func.attr))

    assert violations == []


class _HostileCallable:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, *_args, **_kwargs):
        self.calls.append("__call__")
        raise AssertionError("__call__")

    def __format__(self, _spec):
        self.calls.append("__format__")
        raise AssertionError("__format__")

    def __repr__(self):
        self.calls.append("__repr__")
        raise AssertionError("__repr__")

    def __str__(self):
        self.calls.append("__str__")
        raise AssertionError("__str__")


def test_stage1928_retry_policy_rejects_caller_owned_retry_callbacks_without_calling_hooks():
    retry_max = _HostileCallable()
    retryable = _HostileCallable()

    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        {},
        False,
        worker_once=lambda path, _prev, _timeout: (path, {"error": "transient"}),
        retry_max=retry_max,
        is_retryable_failure=retryable,
        clear_integrity=_clear_integrity,
        get_integrity=lambda _path: {},
        set_integrity=_set_integrity,
        report_retry_log_failure=_report_retry_log_failure,
    ))

    assert retry_max.calls == []
    assert retryable.calls == []
    failures = result["scan_integrity"]["file_retry_failures"]
    callbacks = {item["callback_name"] for item in failures}
    assert "retry_max" in callbacks
    assert "is_retryable_failure" in callbacks


def test_stage1928_retry_integrity_and_publication_reject_caller_owned_callbacks_without_calling_hooks():
    get_integrity = _HostileCallable()
    report = _HostileCallable()

    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        {},
        False,
        worker_once=lambda path, _prev, _timeout: (path, {"error": "transient"}),
        retry_max=lambda _prev: 1,
        is_retryable_failure=lambda _value: True,
        clear_integrity=lambda _path: (_ for _ in ()).throw(RuntimeError("clear failed")),
        get_integrity=get_integrity,
        set_integrity=_set_integrity,
        report_retry_log_failure=report,
    ))

    assert get_integrity.calls == []
    assert report.calls == []
    integrity = result["scan_integrity"]
    assert integrity["queue_retry_policy_callback_failed"] is True
    assert integrity["queue_retry_log_publication_failed"] is True
    callbacks = {item.get("callback_name") for item in integrity["file_retry_failures"]}
    assert "get_integrity" in callbacks


def test_stage1928_result_scan_integrity_rejects_hostile_mapping_without_hooks():
    hostile = _HostileMapping()

    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        {},
        False,
        worker_once=lambda path, _prev, _timeout: (path, {"scan_integrity": hostile}),
        retry_max=lambda _prev: 0,
        is_retryable_failure=lambda _value: False,
        clear_integrity=_clear_integrity,
        get_integrity=lambda _path: {},
        set_integrity=_set_integrity,
        report_retry_log_failure=_report_retry_log_failure,
    ))

    assert hostile.calls == []
    evidence = result["scan_integrity"]["queue_retry_policy_callback_evidence"]
    assert evidence["callback_name"] == "result_scan_integrity_schema"
