from __future__ import annotations

import inspect
from threading import Event, Thread

import Virus_Scan.scheduler.workers.process_queue_child_job as child_job
from Virus_Scan.scheduler.workers.claim_heartbeat import WorkerClaimHeartbeatHandle
from Virus_Scan.scheduler.workers.process_queue_child_heartbeat_boundary import (
    stop_process_queue_child_heartbeat,
)


class HostileHeartbeatHandle:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __getattribute__(self, name):
        type(self).touched += 1
        raise RuntimeError("must not inspect heartbeat handle")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("must not stringify heartbeat handle")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("must not repr heartbeat handle")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("must not format heartbeat handle")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("must not bool heartbeat handle")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("must not iterate heartbeat handle")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("must not float heartbeat handle")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("must not int heartbeat handle")


def test_stage1808_child_heartbeat_rejects_hostile_handle_without_hooks() -> None:
    HostileHeartbeatHandle.reset()
    failures: list[tuple[str, str]] = []

    status = stop_process_queue_child_heartbeat(
        HostileHeartbeatHandle(),
        failure_recorder=lambda label, exc: failures.append((label, type(exc).__name__)),
    )

    assert HostileHeartbeatHandle.touched == 0
    assert status["signalled"] is False
    assert status["joined"] is False
    assert status["alive"] is False
    assert status["error"] == "process_queue_child_heartbeat_handle_rejected"
    assert failures == [("process_queue_child_heartbeat_handle_rejected", "RuntimeError")]


def test_stage1808_child_heartbeat_stops_exact_worker_handle() -> None:
    stop_event = Event()
    thread = Thread(target=lambda: stop_event.wait(10.0), daemon=True)
    thread.start()
    handle = WorkerClaimHeartbeatHandle(
        stop_event=stop_event,
        thread=thread,
        interval_sec=1.0,
        worker_id="worker-a",
    )

    status = stop_process_queue_child_heartbeat(handle, join_timeout=1.0)

    assert status["signalled"] is True
    assert status["joined"] is True
    assert status["alive"] is False
    assert status["error"] == ""
    assert stop_event.is_set() is True
    assert thread.is_alive() is False


def test_stage1808_process_queue_child_job_uses_no_hook_heartbeat_boundary() -> None:
    src = inspect.getsource(child_job)

    assert "stop_process_queue_child_heartbeat(" in src
    assert "getattr(hb_handle" not in src
    assert 'getattr(hb_handle, "stop_event"' not in src
    assert 'getattr(hb_handle, "thread"' not in src
