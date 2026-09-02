import inspect

import Virus_Scan.scheduler.queue.claim_heartbeat as queue_claim_heartbeat
import Virus_Scan.scheduler.workers.claim_heartbeat as worker_claim_heartbeat
import Virus_Scan.scheduler.workers.process_queue_child_job as child_job
from Virus_Scan.scheduler.workers.inmemory_worker_thread_progress import InMemoryWorkerThreadProgress


def test_stage730_claim_heartbeat_thread_lifecycle_is_worker_owned():
    queue_src = inspect.getsource(queue_claim_heartbeat)
    worker_src = inspect.getsource(worker_claim_heartbeat)
    assert "def _umige_start_claim_heartbeat" not in queue_src
    assert "def _umige_stop_claim_heartbeat" not in queue_src
    assert "Thread(" not in queue_src
    assert "def start_worker_claim_heartbeat" in worker_src
    assert "WorkerClaimHeartbeatHandle" in worker_src


def test_stage730_child_job_receives_queue_heartbeat_writer_as_explicit_dependency():
    fields = getattr(child_job.ProcessQueueChildJobRequest, "__dataclass_fields__")
    assert "claim_heartbeat_update" in fields
    src = inspect.getsource(child_job)
    assert "Virus_Scan.scheduler.queue.claim_heartbeat" not in src
    assert "update_callback=request.claim_heartbeat_update" in src


def test_stage730_inmemory_worker_thread_progress_is_worker_owned():
    assert InMemoryWorkerThreadProgress.__module__ == "Virus_Scan.scheduler.workers.inmemory_worker_thread_progress"
