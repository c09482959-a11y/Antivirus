from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, wait

from Virus_Scan.runtime.provenance import provenance_snapshot, reset_provenance_epoch
from Virus_Scan.scheduler.workers.lifecycle_boundary import SchedulerIsolationBoundary, WorkerLifecycleEvent


def _drive_lifecycle(boundary: SchedulerIsolationBoundary, index: int) -> None:
    queue_id = "stage1982-q-" + str(index)
    worker_id = "stage1982-w-" + str(index)
    boundary.transition(WorkerLifecycleEvent(worker_id, queue_id, "new", "queued"))
    boundary.transition(WorkerLifecycleEvent(worker_id, queue_id, "queued", "claimed"))
    boundary.transition(WorkerLifecycleEvent(worker_id, queue_id, "claimed", "running"))
    boundary.transition(WorkerLifecycleEvent(worker_id, queue_id, "running", "completed"))


def test_stage1982_worker_lifecycle_concurrent_validation_gate_completes() -> None:
    reset_provenance_epoch()
    boundary = SchedulerIsolationBoundary(scheduler_id="stage1982")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_drive_lifecycle, boundary, index) for index in range(100)]
        done, pending = wait(futures, timeout=10)
        assert not pending
        for future in done:
            future.result()
    snapshot = boundary.snapshot()
    assert len(snapshot["states"]) == 100
    assert all(state == "completed" for state in snapshot["states"].values())
    events = provenance_snapshot(canonical=True)["events"]
    assert any(event.get("event_type") == "worker_lifecycle" for event in events)
