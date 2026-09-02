"""In-memory scheduler job registry construction ownership."""
from __future__ import annotations

from collections import deque
from typing import Callable


def build_inmemory_job_registry(all_files: object, *, per_file_timeout_sec: object, timeout_budget_factory: Callable[..., object]) -> object:
    """Create the mutable queue-owned job registry for one scheduler run.

    The live registry remains mutable because the scheduler updates worker-owned
    state transitions, but construction and initial queue ownership now live in
    ownership/ rather than inside the in-memory orchestration loop.
    """

    pending = deque((i, f, 0) for i, f in enumerate(all_files))
    job_records = {}
    for i, file_path in enumerate(all_files):
        budget = timeout_budget_factory(
            file_path,
            configured_timeout_seconds=per_file_timeout_sec,
            method="inmemory_file_scan",
        )
        job_records[i] = {
            "file": file_path,
            "attempt": 0,
            "generation": 0,
            "state": "pending",
            "pid": None,
            "queued_at": 0.0,
            "assigned_at": 0.0,
            "running_at": 0.0,
            "started_at": 0.0,
            "last_heartbeat": 0.0,
            "last_progress_time": 0.0,
            "last_progress_ns": 0,
            "last_progress_signature": None,
            "heartbeat_seq": 0,
            "stage": "pending",
            "progress_counter": 0,
            "bytes_processed": 0,
            "cancel_requested_at": 0.0,
            "cost": {"weight": 1, "stage": "light", "heavy": False},
            "timeout_budget": budget.as_evidence(),
            "history": [],
        }
    return pending, job_records
