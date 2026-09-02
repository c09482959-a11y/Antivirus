from __future__ import annotations

import ast
import inspect
from pathlib import Path

from Virus_Scan.scheduler.ownership import raw_queue_publish
from Virus_Scan.scheduler.ownership.raw_queue_publish import (
    RawQueuePublishDependencies,
    publish_raw_stage_job,
)
from Virus_Scan.scheduler.queue.identity_lock import IdentityLockAcquireDecision, IdentityLockReleaseDecision


class HostileRawPublishValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("format hook executed")

    def __int__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("int hook executed")

    def __float__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("float hook executed")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("bool hook executed")


class _NumberDeps:
    def __init__(self) -> None:
        self.suppressed: list[str] = []

    def record_suppressed(self, where: str, _exc: BaseException) -> None:
        self.suppressed.append(where)


def _raw_dirs(root: Path):
    dirs = tuple(root / name for name in ("pending", "active", "done", "failed", "accumulators", "locks"))
    for directory in dirs:
        directory.mkdir(parents=True, exist_ok=True)
    return dirs


def _deps(**overrides):
    data = dict(
        global_raw_dirs=_raw_dirs,
        global_raw_file_id=lambda _file_text: "generated",
        raw_queue_live_count=lambda _queue_dir: 0,
        runtime_value=lambda _name, default=None: default,
        runtime_int=lambda _name, default=0: default,
        umige_retry_max=lambda _stage: 1,
        job_identity=lambda job, _fallback=None: "identity:" + job["file_id"],
        acquire_identity_lock_decision=lambda queue_dir, _ident: IdentityLockAcquireDecision(True, Path(queue_dir) / "lock", "process_queue_identity_lock_acquired"),
        release_identity_lock_decision=lambda _lock: IdentityLockReleaseDecision(True, "process_queue_identity_lock_released"),
        enqueue_guard=lambda *_args, **_kwargs: True,
        write_json_durable=lambda tmp, final, payload, *, log_context: True,
        identity_index_invalidate=lambda _queue_dir: None,
        hybrid_queue_state_delta=lambda _queue_dir, **_delta: None,
        safe_unlink=lambda path, **_kwargs: None,
        record_suppressed=lambda _where, _exc: None,
    )
    data.update(overrides)
    return RawQueuePublishDependencies(**data)


def test_stage1871_raw_publish_number_field_names_reject_hostile_field_without_hooks():
    HostileRawPublishValue.reset()
    hostile_field = HostileRawPublishValue()
    hostile_value = HostileRawPublishValue()
    deps = _NumberDeps()

    value = raw_queue_publish._safe_job_number({hostile_field: hostile_value}, hostile_field, deps, default=7)

    assert HostileRawPublishValue.touched == 0
    assert value == 7
    assert deps.suppressed == ["raw_publish_field_parse_failed"]


def test_stage1871_raw_publish_write_failure_cleans_string_tmp_path_without_hook_materialization(tmp_path):
    events: list[tuple[str, object]] = []

    def failing_write(tmp, final, payload, *, log_context):
        events.append(("write_name", (Path(tmp).name, Path(final).name, payload["file_id"], log_context)))
        raise OSError("durable write failed")

    def safe_unlink(path, *, log_context):
        events.append(("unlink_path_type", type(path)))
        events.append(("unlink_path_name", Path(path).name))
        events.append(("unlink_context", log_context))

    suppressed: list[str] = []
    deps = _deps(
        write_json_durable=failing_write,
        safe_unlink=safe_unlink,
        record_suppressed=lambda where, _exc: suppressed.append(where),
    )
    job = {"file": "game.bin", "file_id": "fid", "seq": 2, "attempt": 3, "collector": "raw", "max_retries": 4}

    result = publish_raw_stage_job(tmp_path, job, deps)

    assert result.published is False
    assert result.reason == "raw_publish_write_failed_closed"
    assert ("unlink_path_type", str) in events
    assert ("unlink_path_name", "raw_fid_000002_a03_raw.json.tmp") in events
    assert ("unlink_context", "raw_publish_tmp_cleanup") in events
    assert "raw_publish_write_failed_closed" in suppressed


def test_stage1871_raw_publish_source_has_no_field_name_fstrings_or_except_returns():
    source = inspect.getsource(raw_queue_publish)
    tree = ast.parse(source)
    returns_in_except = [node.lineno for handler in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)) for node in ast.walk(handler) if isinstance(node, ast.Return)]
    forbidden = (
        'f"raw_publish_{field}_parse_failed"',
        'f"raw_publish_{field}_non_finite"',
        'f"raw_{fid}_{seq:06d}_a{attempt_part:02d}_{collector}.json"',
        'deps.safe_unlink(tmp, log_context="raw_publish_tmp_cleanup")',
    )
    offenders = [token for token in forbidden if token in source]

    assert offenders == []
    assert returns_in_except == []
    assert "raw_publish_" + str.__str__("max_retries") + "_parse_failed" == "raw_publish_max_retries_parse_failed"
