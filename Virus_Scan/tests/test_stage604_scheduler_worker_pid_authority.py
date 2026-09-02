from pathlib import Path
import os

from Virus_Scan.scheduler.workers import process_liveness as worker_authority


def test_worker_pid_liveness_is_worker_authority_owned():
    events = []
    assert worker_authority.check_process_queue_worker_liveness(os.getpid(), record_suppressed=lambda *args, **kwargs: events.append((args, kwargs))).alive is True
    assert worker_authority.check_process_queue_worker_liveness(0, record_suppressed=lambda *args, **kwargs: events.append((args, kwargs))).alive is False
    assert events == []


def test_worker_pid_liveness_has_single_authority_owner():
    assert worker_authority.check_process_queue_worker_liveness.__module__.endswith("workers.process_liveness")


def test_execution_process_queue_liveness_module_removed_after_authority_migration():
    assert not Path("Virus_Scan/scheduler/execution/process_queue_liveness.py").exists()
