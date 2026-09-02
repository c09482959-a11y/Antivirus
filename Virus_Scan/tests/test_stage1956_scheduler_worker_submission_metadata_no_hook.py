from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from Virus_Scan.scheduler.workers.inmemory_worker_submission import (
    _owned_task_meta_value,
    submit_inmemory_worker_task,
)


class HostileTaskMeta(dict):
    get_calls = 0
    bool_calls = 0
    items_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.get_calls = 0
        cls.bool_calls = 0
        cls.items_calls = 0

    def get(self, *_args, **_kwargs):
        type(self).get_calls += 1
        raise AssertionError("caller-owned mapping get hook executed")

    def __bool__(self):
        type(self).bool_calls += 1
        raise AssertionError("caller-owned mapping bool hook executed")

    def items(self):
        type(self).items_calls += 1
        raise AssertionError("caller-owned mapping items hook executed")


class FailingThreadPool:
    def submit(self, *_args, **_kwargs):
        raise RuntimeError("thread pool unavailable")


def test_stage1956_task_meta_reader_rejects_hostile_mapping_subclasses_without_hooks() -> None:
    HostileTaskMeta.reset()
    hostile = HostileTaskMeta(job_id=91, path="hostile.bin", attempt=7)

    assert _owned_task_meta_value(hostile, "job_id") is None
    assert _owned_task_meta_value(hostile, "path") is None
    assert _owned_task_meta_value(hostile, "attempt") is None

    assert HostileTaskMeta.get_calls == 0
    assert HostileTaskMeta.bool_calls == 0
    assert HostileTaskMeta.items_calls == 0


def test_stage1956_task_meta_reader_preserves_exact_dict_worker_metadata() -> None:
    meta = {"job_id": 31, "path": "owned.bin", "attempt": 6}

    assert _owned_task_meta_value(meta, "job_id") == 31
    assert _owned_task_meta_value(meta, "path") == "owned.bin"
    assert _owned_task_meta_value(meta, "attempt") == 6


def test_stage1956_submission_failure_uses_owned_metadata_without_mapping_get_route() -> None:
    result_items = []
    task = SimpleNamespace(job_id=41, path="submit-owned.bin", attempt=3)
    worker_deps = SimpleNamespace(
        result_put=lambda item: result_items.append(item),
        worker_error_result=lambda path, exc: {"file": path, "error": "worker failed", "scan_integrity": {}},
    )

    submission = submit_inmemory_worker_task(
        task=task,
        tpool=FailingThreadPool(),
        active={},
        execute_job=lambda *_args, **_kwargs: None,
        worker_execution_deps=worker_deps,
        worker_config={},
        cancel_table={},
        heartbeat_table={},
        heartbeat_flags={},
        completed_jobs=0,
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda _stage, _exc: None,
    )

    assert submission.submitted is False
    assert submission.job_id == 41
    assert submission.attempt == 3
    assert result_items[0][1] == 41
    assert result_items[0][2] == "submit-owned.bin"
    assert result_items[0][6] == 3


def test_stage1956_submission_source_removes_task_meta_get_hook_route() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "workers" / "inmemory_worker_submission.py").read_text(encoding="utf-8")

    assert "task_meta.get(" not in source
    assert "_owned_task_meta_value(task_meta, \"job_id\")" in source
    assert "_owned_task_meta_value(task_meta, \"path\")" in source
    assert "_owned_task_meta_value(task_meta, \"attempt\")" in source
