from __future__ import annotations

from Virus_Scan.scheduler.workers.ipc_lifecycle import close_owned_ipc_queue, shutdown_worker_processes


class FakeQueue:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def cancel_join_thread(self) -> None:
        self.calls.append("cancel_join_thread")

    def close(self) -> None:
        self.calls.append("close")

    def join_thread(self) -> None:
        self.calls.append("join_thread")


class FakeProc:
    def __init__(self, *, alive: bool) -> None:
        self.alive = alive
        self.calls: list[str] = []

    def join(self, timeout=None) -> None:  # noqa: ANN001
        self.calls.append(f"join:{timeout}")
        if self.alive and timeout == 0.0:
            return
        self.alive = False

    def is_alive(self) -> bool:
        return self.alive

    def terminate(self) -> None:
        self.calls.append("terminate")
        self.alive = False

    def close(self) -> None:
        self.calls.append("close")


def test_stage387_scheduler_owned_queue_detaches_feeder_before_close() -> None:
    queue = FakeQueue()
    status = close_owned_ipc_queue(queue, join_thread=False)

    assert status == {"cancel_join_thread": True, "closed": True, "joined": False, "errors": []}
    assert queue.calls == ["cancel_join_thread", "close"]


def test_stage387_worker_shutdown_finalizes_process_handles_after_terminate() -> None:
    alive = FakeProc(alive=True)
    exited = FakeProc(alive=False)

    summary = shutdown_worker_processes([alive, exited], exit_grace_sec=0.0, terminate=True)

    assert summary["terminated"] == 1
    assert summary["alive_after"] == 0
    assert "close" in alive.calls
    assert "close" in exited.calls

class SlowTerminatingProc:
    def __init__(self) -> None:
        self.alive = True
        self.terminated = False
        self.calls: list[tuple[str, object]] = []

    def join(self, timeout=None) -> None:  # noqa: ANN001
        self.calls.append(("join", timeout))
        if self.terminated and timeout and timeout > 0:
            self.alive = False

    def is_alive(self) -> bool:
        return self.alive

    def terminate(self) -> None:
        self.calls.append(("terminate", None))
        self.terminated = True

    def close(self) -> None:
        self.calls.append(("close", None))


def test_stage1641_worker_shutdown_joins_and_closes_after_terminate() -> None:
    proc = SlowTerminatingProc()

    summary = shutdown_worker_processes([proc], exit_grace_sec=0.0, terminate=True)

    assert summary["terminated"] == 1
    assert summary["post_terminate_joined"] == 1
    assert summary["alive_after"] == 0
    assert summary["closed"] == 1
    assert ("terminate", None) in proc.calls
    assert any(call == "join" and timeout and timeout > 0 for call, timeout in proc.calls)
    assert ("close", None) in proc.calls
