from __future__ import annotations

from pathlib import Path

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.workers.process_snapshots import ProcessQueueWorkerSnapshot
from Virus_Scan.scheduler.workers.publication_status import safe_publication_status
from Virus_Scan.scheduler.workers.retire_tokens import request_queue_worker_retire
from Virus_Scan.scheduler.workers.shared_heartbeat_evidence import record_shared_heartbeat_failure
from Virus_Scan.scheduler.workers.spawn import ProcessQueueWorkerSpawnRequest, build_process_queue_worker_command


SCHEDULER_WORKERS = Path(__file__).resolve().parents[1] / "scheduler" / "workers"


class HostileValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self, _name: str) -> object:
        type(self).touched += 1
        raise AssertionError("caller-owned hook executed")

    def __bool__(self):  # pragma: no cover - failure proves unsafe conversion
        return self._touch("__bool__")

    def __float__(self):  # pragma: no cover
        return self._touch("__float__")

    def __format__(self, _spec):  # pragma: no cover
        return self._touch("__format__")

    def __fspath__(self):  # pragma: no cover
        return self._touch("__fspath__")

    def __int__(self):  # pragma: no cover
        return self._touch("__int__")

    def __iter__(self):  # pragma: no cover
        return self._touch("__iter__")

    def __repr__(self):  # pragma: no cover
        return self._touch("__repr__")

    def __str__(self):  # pragma: no cover
        return self._touch("__str__")


class HostileException(Exception):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("exception repr hook executed")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("exception str hook executed")


def _assert_untouched() -> None:
    assert HostileValue.touched == 0
    assert HostileException.touched == 0


def test_stage1960_worker_backlog_sources_have_no_scheduler_scalar_defaults_or_fstrings() -> None:
    for relative in (
        "process_snapshots.py",
        "publication_status.py",
        "retire_tokens.py",
        "shared_heartbeat_evidence.py",
        "spawn_command_support.py",
        "spawn_dispatch.py",
    ):
        source = (SCHEDULER_WORKERS / relative).read_text(encoding="utf-8")
        for snippet in (
            "fallback=",
            "default=",
            "scheduler_int",
            "scheduler_float",
            "scheduler_bool",
            'f"',
            "f'",
        ):
            assert snippet not in source


def test_stage1960_worker_snapshot_publication_retire_and_heartbeat_reject_hostile_values_without_hooks(tmp_path) -> None:
    clear_failure_records()
    HostileValue.reset()
    HostileException.reset()

    snapshot = ProcessQueueWorkerSnapshot(HostileValue(), (), ())
    publication_status, publication_reason = safe_publication_status(HostileValue())
    retired = request_queue_worker_retire(tmp_path, HostileValue())
    record_shared_heartbeat_failure(
        operation=HostileValue(),
        job_id=HostileValue(),
        generation=HostileValue(),
        exc=HostileException("hidden"),
    )

    assert snapshot.live_count == 0
    assert "process_worker_snapshot_live_count_rejected" in snapshot.suppressed_failures
    assert publication_status is False
    assert publication_reason == "scheduler_worker_publication_status_rejected"
    assert retired == 0
    wheres = tuple(record.get("where", "") for record in failure_snapshot().get("records", ()))
    assert "queue_worker_retire_count_rejected" in wheres
    assert "worker_shared_heartbeat_heartbeat_failed" in wheres
    _assert_untouched()


def test_stage1960_spawn_command_rejects_hostile_boundary_scalars_without_hooks() -> None:
    HostileValue.reset()
    HostileException.reset()

    request = ProcessQueueWorkerSpawnRequest(
        root=HostileValue(),
        queue_dir=HostileValue(),
        output=HostileValue(),
        worker_index=HostileValue(),
        script_path=HostileValue(),
        python_executable=HostileValue(),
        env_base={},
        progress_every=HostileValue(),
        partial_output_every=HostileValue(),
        slow_file_warn_sec=HostileValue(),
        per_file_timeout_sec=HostileValue(),
        throttle_sec=HostileValue(),
        strict=HostileValue(),
        scan_session_manifest_path=Path("scan_session_snapshot.json"),
    )

    command = build_process_queue_worker_command(request)

    assert command[0] == "<rejected-python_executable>"
    assert command[1] == "<rejected-script_path>"
    assert command[command.index("--per-file-timeout") + 1] == "0"
    assert command[command.index("--progress-every") + 1] == "10"
    assert command[command.index("--partial-output-every") + 1] == "0"
    assert command[command.index("--slow-file-warn") + 1] == "0.0"
    _assert_untouched()
