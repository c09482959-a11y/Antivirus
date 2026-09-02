from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.ipc_lifecycle_common import (
    record_method_rejection,
    stop_worker_heartbeat,
    worker_process_method,
    worker_queue_method,
)


class OwnedQueue:
    def __init__(self) -> None:
        self.cancelled = False

    def cancel_join_thread(self) -> None:
        self.cancelled = True


class OwnedThread:
    def __init__(self) -> None:
        self.join_timeout = -1.0

    def join(self, *, timeout: float) -> None:
        self.join_timeout = timeout

    def is_alive(self) -> bool:
        return False


class OwnedEvent:
    def __init__(self) -> None:
        self.signalled = False

    def set(self) -> None:
        self.signalled = True


class HostileAttributeObject:
    touched = 0

    def __getattribute__(self, name):  # pragma: no cover - failure proves unsafe probing
        type(self).touched += 1
        raise AssertionError(f"caller-owned attribute hook invoked for {name}")


def test_stage2137_ipc_lifecycle_common_has_no_local_dynamic_typing_surface() -> None:
    source = Path("Virus_Scan/scheduler/workers/ipc_lifecycle_common.py").read_text()

    assert "typing import" not in source
    assert "object | None" in source
    assert "FailureRecorder" in source


def test_stage2137_worker_method_domain_adapters_return_typed_callable_decisions() -> None:
    queue = OwnedQueue()
    method, reason = worker_queue_method(queue, "cancel_join_thread")

    assert reason == ""
    assert method is not None
    method()
    assert queue.cancelled is True

    rejected, reject_reason = worker_process_method(queue, "cancel_join_thread")
    assert rejected is None
    assert reject_reason == "unsafe_worker_lifecycle_name_rejected"


def test_stage2137_record_method_rejection_materializes_recorder_failure_evidence() -> None:
    container = {"errors": "not-a-list"}

    def failing_recorder(_label: str, _exc: BaseException) -> None:
        raise RuntimeError("recorder boom")

    record_method_rejection(
        container,
        "queue_close_rejected",
        "unsafe_worker_lifecycle_descriptor_rejected",
        failure_recorder=failing_recorder,
    )

    assert container["errors"] == [
        {
            "stage": "queue_close_rejected",
            "error": "unsafe_worker_lifecycle_descriptor_rejected",
        },
        {"stage": "queue_close_rejected_recorder_failed", "error": "RuntimeError: recorder boom"},
    ]


def test_stage2137_stop_worker_heartbeat_accepts_owned_event_thread_without_hooks() -> None:
    event = OwnedEvent()
    thread = OwnedThread()

    status = stop_worker_heartbeat(event, thread, join_timeout=-4.0)

    assert status == {"signalled": True, "joined": True, "alive": False, "error": ""}
    assert event.signalled is True
    assert thread.join_timeout == 0.0


def test_stage2137_worker_lifecycle_common_rejects_hostile_hooks_without_touching_them() -> None:
    HostileAttributeObject.touched = 0

    method, reason = worker_queue_method(HostileAttributeObject(), "close")
    status = stop_worker_heartbeat(HostileAttributeObject(), None)

    assert method is None
    assert reason == "unsafe_worker_lifecycle_getattribute_rejected"
    assert status["error"] == "unsafe_worker_lifecycle_getattribute_rejected"
    assert HostileAttributeObject.touched == 0
