from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.ipc_lifecycle import close_owned_ipc_queue, shutdown_worker_processes
from Virus_Scan.scheduler.workers.ipc_lifecycle_common import worker_lifecycle_float, worker_lifecycle_int


class HostileScalar:
    touched = 0

    def __bool__(self):  # pragma: no cover - failure proves unsafe truthiness
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ invoked")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __int__ invoked")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __float__ invoked")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ invoked")


class RecorderFailure(RuntimeError):
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned recorder exception __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned recorder exception __repr__ invoked")


class ClosingQueue:
    def cancel_join_thread(self) -> None:
        raise RuntimeError("cancel failed")


class AliveProcess:
    def __init__(self) -> None:
        self.alive = True
        self.calls: list[str] = []

    def join(self, timeout=None) -> None:  # noqa: ANN001
        self.calls.append("join")

    def is_alive(self) -> bool:
        return self.alive

    def terminate(self) -> None:
        self.calls.append("terminate")
        self.alive = False

    def close(self) -> None:
        self.calls.append("close")


def _failing_recorder(_stage: str, _exc: BaseException) -> None:
    raise RecorderFailure("recorder failed")


def test_stage1958_ipc_lifecycle_flags_reject_hostile_scalars_without_hooks() -> None:
    HostileScalar.touched = 0
    hostile = HostileScalar()

    queue_status = close_owned_ipc_queue(ClosingQueue(), join_thread=hostile, failure_recorder=_failing_recorder)
    proc = AliveProcess()
    summary = shutdown_worker_processes([proc], terminate=hostile, exit_grace_sec=hostile, post_terminate_join_sec=hostile)

    assert queue_status["errors"][1]["stage"] == "queue_cancel_join_thread_failed_recorder_failed"
    assert summary["terminated"] == 0
    assert proc.calls == ["join"]
    assert summary["alive_after"] == 1
    assert worker_lifecycle_int(hostile, 7) == 7
    assert worker_lifecycle_float(hostile, 2.5) == 2.5
    assert HostileScalar.touched == 0
    assert RecorderFailure.touched == 0


def test_stage1958_ipc_lifecycle_source_has_no_fallback_or_label_fstring_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    source_paths = (
        root / "scheduler" / "workers" / "ipc_lifecycle.py",
        root / "scheduler" / "workers" / "ipc_lifecycle_common.py",
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in source_paths)

    assert "fallback=" not in combined
    assert "default=" not in combined
    assert 'f"{label}_recorder_failed"' not in combined
    assert "safe_worker_thread_progress_evidence_inputs" not in combined
