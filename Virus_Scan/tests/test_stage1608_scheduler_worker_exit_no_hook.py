from __future__ import annotations

import ast
from pathlib import Path

import pytest

from Virus_Scan.scheduler.workers.process_queue_worker_exit import (
    ProcessQueueWorkerExitDependencies,
    ProcessQueueWorkerExitRequest,
    reconcile_process_queue_worker_exits,
)


class HostileWorkerExitResult:
    touched = 0

    @property
    def as_evidence(self):
        type(self).touched += 1
        raise RuntimeError("as_evidence must not be touched")

    @property
    def status(self):
        type(self).touched += 1
        raise RuntimeError("status must not be touched")

    @property
    def infrastructure_failed(self):
        type(self).touched += 1
        raise RuntimeError("infrastructure_failed must not be touched")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("__int__ must not be touched")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("__bool__ must not be touched")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("__str__ must not be touched")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("__repr__ must not be touched")


class HostileWorkerOutput:
    touched = 0

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("__fspath__ must not be touched")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("__str__ must not be touched")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("__repr__ must not be touched")


class HostileWorkerIndex:
    touched = 0

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("__int__ must not be touched")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("__str__ must not be touched")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("__repr__ must not be touched")


def _deps(return_value, log_messages):
    def wait_for_worker_exit(*_args, **_kwargs):
        return return_value

    return ProcessQueueWorkerExitDependencies(
        wait_for_worker_exit=wait_for_worker_exit,
        record_issue=lambda *_args, **_kwargs: None,
        log_error=log_messages.append,
    )


def test_stage1608_worker_exit_rejects_hostile_result_without_hooks():
    HostileWorkerExitResult.touched = 0
    HostileWorkerOutput.touched = 0
    HostileWorkerIndex.touched = 0
    log_messages: list[str] = []

    result = reconcile_process_queue_worker_exits(
        ProcessQueueWorkerExitRequest(
            procs=((HostileWorkerIndex(), object(), HostileWorkerOutput(), ()),),
            strict=False,
            had_error=False,
        ),
        _deps(HostileWorkerExitResult(), log_messages),
    )

    assert HostileWorkerExitResult.touched == 0
    assert HostileWorkerOutput.touched == 0
    assert HostileWorkerIndex.touched == 0
    assert result.had_error is True
    assert result.exit_evidence
    evidence = result.exit_evidence[0]
    assert evidence["worker_exit_result_unsupported"] is True
    assert evidence["worker_exit_result_type"] == "HostileWorkerExitResult"
    assert evidence["worker_exit_status"] == -1
    assert "queue_worker_exit_result_unsupported" in tuple(evidence["worker_failure_markers"])
    assert log_messages
    assert "Hostile" not in log_messages[0]


def test_stage1608_worker_exit_strict_raises_without_hostile_hooks():
    HostileWorkerExitResult.touched = 0
    HostileWorkerOutput.touched = 0
    log_messages: list[str] = []

    with pytest.raises(RuntimeError, match="process queue worker 1 failed with status -1"):
        reconcile_process_queue_worker_exits(
            ProcessQueueWorkerExitRequest(
                procs=((1, object(), HostileWorkerOutput(), ()),),
                strict=True,
                had_error=False,
            ),
            _deps(HostileWorkerExitResult(), log_messages),
        )

    assert HostileWorkerExitResult.touched == 0
    assert HostileWorkerOutput.touched == 0
    assert log_messages


def test_stage1959_worker_exit_sources_have_no_fallback_or_fstring_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    sources = (
        (root / "scheduler" / "workers" / "process_queue_worker_exit.py").read_text(encoding="utf-8"),
        (root / "scheduler" / "workers" / "process_queue_worker_exit_evidence.py").read_text(encoding="utf-8"),
    )
    combined = "\n".join(sources)

    assert "fallback" not in combined
    assert "scheduler_int" not in combined
    assert "default=" not in combined
    for source in sources:
        assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(ast.parse(source)))


def test_stage2208_worker_exit_evidence_has_no_any_surface() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "workers" / "process_queue_worker_exit_evidence.py").read_text(encoding="utf-8")

    assert "typing import Any" not in source
    assert ": Any" not in source
    assert "dict[str, Any]" not in source


