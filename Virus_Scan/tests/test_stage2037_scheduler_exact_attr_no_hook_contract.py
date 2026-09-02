from __future__ import annotations

from types import SimpleNamespace

from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.workers.cleanup import WorkerExitWaitResult
from Virus_Scan.scheduler.workers.inmemory_worker_job_publication import running_publication_evidence
from Virus_Scan.scheduler.workers.process_queue_worker_exit_evidence import _worker_exit_result_evidence


class HostileSpoof:
    calls = 0

    def __getattribute__(self, name: str):
        type(self).calls += 1
        raise AssertionError("caller-owned __getattribute__ must not run")


def test_stage2037_scheduler_exact_attr_rejects_spoofed_loaded_owner_without_hooks() -> None:
    spoof_type = type(
        "InMemoryWorkerJobExecutionRequest",
        (HostileSpoof,),
        {"__module__": "Virus_Scan.scheduler.workers.inmemory_worker_job"},
    )
    spoof = spoof_type()
    HostileSpoof.calls = 0

    value = scheduler_exact_attr(
        spoof,
        "job_id",
        module_name="Virus_Scan.scheduler.workers.inmemory_worker_job",
        type_name="InMemoryWorkerJobExecutionRequest",
        default="rejected",
    )

    assert value == "rejected"
    assert HostileSpoof.calls == 0


def test_stage2037_running_publication_rejects_spoofed_request_without_hooks() -> None:
    spoof_type = type(
        "InMemoryWorkerJobExecutionRequest",
        (HostileSpoof,),
        {"__module__": "Virus_Scan.scheduler.workers.inmemory_worker_job"},
    )
    spoof = spoof_type()
    HostileSpoof.calls = 0

    evidence = running_publication_evidence(spoof, RuntimeError("boom"))

    assert evidence.job_id == 0
    assert evidence.generation == 0
    assert HostileSpoof.calls == 0


def test_stage2037_worker_exit_evidence_uses_exact_owned_fields() -> None:
    result = WorkerExitWaitResult(
        worker_idx=2,
        pid=1234,
        output="worker.out",
        status=4,
        timed_out=True,
        cleanup_actions=("terminate",),
        failure_markers=("terminated",),
        reason="worker_final_wait",
    )

    evidence = _worker_exit_result_evidence(result, idx=-1, output="unused")

    assert evidence["worker_idx"] == 2
    assert evidence["worker_pid"] == 1234
    assert evidence["worker_cleanup_actions"] == ("terminate",)
    assert evidence["worker_failure_markers"] == ("terminated",)
    assert evidence["worker_wait_timed_out"] is True


def test_stage2037_touched_scheduler_worker_files_have_no_local_object_getattribute() -> None:
    touched = (
        "Virus_Scan/scheduler/orchestration/inmemory_parent_dispatch.py",
        "Virus_Scan/scheduler/workers/process_queue_worker_exit_evidence.py",
        "Virus_Scan/scheduler/workers/claim_heartbeat.py",
        "Virus_Scan/scheduler/workers/process_queue_child_heartbeat_boundary.py",
        "Virus_Scan/scheduler/workers/inmemory_worker_job_publication.py",
        "Virus_Scan/scheduler/workers/inmemory_worker_heartbeat_message.py",
        "Virus_Scan/scheduler/workers/inmemory_worker_heartbeat_boundary.py",
    )

    offenders = [path for path in touched if "object.__getattribute__" in open(path, encoding="utf-8").read()]

    assert offenders == []
    assert scheduler_exact_attr(SimpleNamespace(value=3), "value", owner_type=SimpleNamespace) == 3
