from __future__ import annotations

from Virus_Scan.scheduler.workers.process_termination import (
    terminate_idle_inmemory_worker_for_toxicity,
    terminate_process_queue_worker_handle,
    terminate_queue_worker_pid,
)


class HostileStr:
    touched = 0

    def __str__(self):
        HostileStr.touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        HostileStr.touched += 1
        raise RuntimeError("do not repr")


class HostileInt:
    touched = 0

    def __int__(self):
        HostileInt.touched += 1
        raise RuntimeError("do not int")


class HostilePidProperty:
    touched = 0

    @property
    def pid(self):
        HostilePidProperty.touched += 1
        raise RuntimeError("do not read pid property")

    def poll(self):
        raise AssertionError("poll should not run after rejected pid")

    def terminate(self):
        raise AssertionError("terminate should not run after rejected pid")


class HostileOwnedJobs:
    touched = 0

    def __bool__(self):
        HostileOwnedJobs.touched += 1
        raise RuntimeError("do not bool")

    def __iter__(self):
        HostileOwnedJobs.touched += 1
        raise RuntimeError("do not iterate")


class OwnedInMemoryProc:
    def __init__(self, pid=77, alive=True):
        self.pid = pid
        self.alive = alive
        self.terminated = False

    def is_alive(self):
        return self.alive

    def terminate(self):
        self.terminated = True
        self.alive = False


def test_stage1617_queue_worker_pid_and_reason_reject_hostile_hooks():
    HostileInt.touched = 0
    HostileStr.touched = 0

    result = terminate_queue_worker_pid(HostileInt(), reason=HostileStr())

    assert HostileInt.touched == 0
    assert HostileStr.touched == 0
    assert result.requested is False
    assert result.terminated is False
    assert result.error == "queue_worker_pid_rejected"
    assert result.reason == "queue_progress_stalled"


def test_stage1617_process_handle_rejects_hostile_pid_property_before_poll_or_terminate():
    HostilePidProperty.touched = 0
    HostileInt.touched = 0
    HostileStr.touched = 0

    result = terminate_process_queue_worker_handle(
        worker_idx=HostileInt(),
        proc=HostilePidProperty(),
        action="terminate",
        reason=HostileStr(),
    )

    assert HostilePidProperty.touched == 0
    assert HostileInt.touched == 0
    assert HostileStr.touched == 0
    assert result.requested is False
    assert result.completed is False
    assert result.error == "process_handle_pid_descriptor_rejected"
    assert result.reason == "worker_cleanup"


def test_stage1617_toxic_worker_owned_jobs_rejects_truthiness_and_iteration_hooks():
    HostileOwnedJobs.touched = 0
    HostileStr.touched = 0
    proc = OwnedInMemoryProc(pid=77, alive=True)

    result = terminate_idle_inmemory_worker_for_toxicity(
        proc=proc,
        toxic_pid=77,
        owned_job_ids=HostileOwnedJobs(),
        reason=HostileStr(),
    )

    assert HostileOwnedJobs.touched == 0
    assert HostileStr.touched == 0
    assert proc.terminated is False
    assert result.requested is False
    assert result.terminated is False
    assert result.error == "owned_job_ids_rejected"
    assert result.reason == "worker_memory_toxic"
