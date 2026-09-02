from __future__ import annotations

def _append_and_return_true(target, value):
    target.append(value)
    return True

from Virus_Scan.scheduler.ownership.inmemory_live_state import InMemoryLiveSchedulerState
from Virus_Scan.scheduler.workers.inmemory_worker_thread_progress import InMemoryWorkerThreadProgress


class _Flags:
    running = 1
    cancel_request = 2
    poisoned_or_retire_mask = 4


def test_inmemory_live_scheduler_state_copies_caller_owned_containers() -> None:
    active = {"job": {"state": "active"}}
    done = {"old"}
    processes = [object()]
    ewma = {"stage": 1}

    state = InMemoryLiveSchedulerState(
        active=active,
        done=done,
        processes=processes,
        ewma_state=ewma,
    )

    active["late"] = {"state": "caller_mutation"}
    done.add("late")
    processes.append(object())
    ewma["stage"] = 9

    assert "late" not in state.active
    assert "late" not in state.done
    assert len(state.processes) == 1
    assert state.ewma_state == {"stage": 1.0}

    state.active["owned"] = {"state": "owned"}
    state.done.add("owned")
    assert "owned" in state.active
    assert "owned" in state.done


def test_worker_thread_progress_snapshots_config_but_preserves_task_meta_publication() -> None:
    cfg = {"worker_rss_limit_mb": "2048"}
    task_meta: dict[str, object] = {}
    heartbeat_calls: list[dict[str, object]] = []

    progress = InMemoryWorkerThreadProgress(
        cfg=cfg,
        job_id="job-1",
        generation=2,
        cancel_table=None,
        heartbeat_table=None,
        heartbeat_flags=_Flags(),
        completed_jobs=0,
        task_meta=task_meta,
        cancel_requested=lambda _table, _job, _generation: False,
        update_shared_heartbeat=lambda *args, **kwargs: _append_and_return_true(heartbeat_calls, dict(kwargs)),
        recoverable_exceptions=(RuntimeError,),
    )

    cfg["worker_rss_limit_mb"] = "1"
    assert progress.cfg == {"worker_rss_limit_mb": "2048"}

    assert progress("scan", inc=3, bytes_delta=11) is True
    assert task_meta["progress_counter"] == 3
    assert task_meta["bytes_processed"] == 11
    assert heartbeat_calls[-1]["progress_counter"] == 3
