from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from types import SimpleNamespace
from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.orchestration.inmemory_parent_message import (
    InMemoryParentMessageRequest,
    handle_inmemory_parent_message,
)

from dataclasses import FrozenInstanceError
from queue import Empty

from Virus_Scan.scheduler.workers.inmemory_worker_assignment import (
    InMemoryWorkerAssignmentPublicationResult,
    InMemoryAssignedTask,
    publish_inmemory_worker_assignment,
)
from Virus_Scan.scheduler.workers.inmemory_worker_intake import (
    InMemoryWorkerTaskIntakeDependencies,
    receive_inmemory_worker_task,
)


class _TaskQueue:
    def __init__(self, items):
        self.items = list(items)

    def get(self, timeout=0.0):
        if not self.items:
            raise Empty()
        return self.items.pop(0)


class _FailingResultQueue:
    def put(self, item):
        raise RuntimeError("assignment channel down")


def test_stage748_assignment_publication_failure_is_immutable_worker_evidence():
    events = []
    result = publish_inmemory_worker_assignment(
        result_put=_FailingResultQueue().put,
        task=InMemoryAssignedTask(job_id=42, path="sample.bin", attempt=3),
        record_scheduler_suppressed=lambda stage, exc: events.append((stage, str(exc))),
        recoverable_exceptions=(RuntimeError,),
    )
    assert isinstance(result, InMemoryWorkerAssignmentPublicationResult)
    assert result.job_id == 42
    assert result.attempt == 3
    assert result.published is False
    assert result.suppressed_failures == 1
    assert result.failure_stage == "inmemory_worker_assignment_publication_failure"
    assert events and events[0][0] == "inmemory_worker_assignment_publication_failure"
    try:
        result.published = True
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("assignment publication evidence must be immutable")


def test_stage748_worker_intake_does_not_report_clean_assignment_when_publication_fails():
    events = []
    intake = receive_inmemory_worker_task(
        task_q=_TaskQueue([(42, "sample.bin", 3)]),
        intake=InMemoryWorkerTaskIntakeDependencies(
            result_put=_FailingResultQueue().put,
            queue_empty_type=Empty,
            recoverable_exceptions=(RuntimeError, ValueError, TypeError, KeyError, AttributeError),
            record_suppressed=lambda stage, exc: events.append((stage, str(exc))),
        ),
    )
    assert intake.task is not None
    assert intake.assignment_published is False
    assert intake.suppressed_failures >= 1
    assert events and events[0][0] == "inmemory_worker_assignment_publication_failure"


def test_stage748_unknown_parent_worker_message_kind_records_evidence():


    clear_failure_records()
    recovery = SimpleNamespace(
        record_lifecycle_request=lambda *_args, **_kwargs: None,
        replace_with_history_transition=lambda _job_id, rec, *_args, **_kwargs: rec,
        request_cancel_only=lambda *_args, **_kwargs: None,
        retry_or_fail=lambda *_args, **_kwargs: True,
    )
    result = handle_inmemory_parent_message(
        InMemoryParentMessageRequest(
            message=("mystery_worker_state", 1, "sample.bin"),
            job_records={},
            active={},
            terminal=set(),
            failed=set(),
            done=set(),
            results=[],
            recovery=recovery,
            state_index=InMemorySchedulerStateIndex(),
            root=None,
            routing_evidence_context=None,
            worker_heartbeats={},
            worker_metrics={},
            heartbeat_flags=SimpleNamespace(poisoned_or_retire_mask=4),
            partial_output_path=None,
            partial_output_every=0,
            partial_writer=None,
            started_at=0.0,
            progress_every=0,
            throttle_sec=0.0,
            result_retainer=lambda _path, result: result,
            derived_cache_writer=lambda _result: False,
        wall_time=lambda: 1.0,
            sleep=lambda _seconds: None,
            recoverable_exceptions=(Exception,),
        )
    )

    assert result.handled is False
    snapshot = failure_snapshot()
    assert any("inmemory_parent_worker_message_unknown_kind_failed" in str(key) for key in snapshot["records"])
