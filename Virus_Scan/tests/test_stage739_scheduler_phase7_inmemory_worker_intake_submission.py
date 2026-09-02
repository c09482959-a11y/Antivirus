from Virus_Scan.tests.support.static_inventory import read_python_file

from dataclasses import FrozenInstanceError
from pathlib import Path
from queue import Empty
import multiprocessing

from Virus_Scan.scheduler.workers.inmemory_worker_process import run_inmemory_longlived_worker
from Virus_Scan.scheduler.workers.inmemory_worker_exit_publication import (
    InMemoryWorkerExitPublicationResult,
    publish_inmemory_worker_exit,
)
from Virus_Scan.scheduler.workers.inmemory_worker_intake import (
    InMemoryWorkerTaskIntakeDependencies,
    InMemoryWorkerTaskIntakeResult,
    receive_inmemory_worker_task,
)
from Virus_Scan.scheduler.workers.inmemory_worker_submission import InMemoryWorkerTaskSubmissionResult, submit_inmemory_worker_task
from Virus_Scan.scheduler.workers.inmemory_worker_job_dependencies import (
    InMemoryWorkerJobDependenciesEvidence,
    build_inmemory_worker_job_dependencies,
)



class _TaskQueue:
    def __init__(self, items):
        self.items = list(items)

    def get(self, timeout=0.0):
        if not self.items:
            raise Empty()
        return self.items.pop(0)


class _ResultQueue:
    def __init__(self, fail=False):
        self.items = []
        self.fail = fail

    def put(self, item):
        if self.fail:
            raise RuntimeError("queue down")
        self.items.append(item)


class _Future:
    pass


class _Pool:
    def submit(self, fn, request, deps):
        return _Future()


def _recorded():
    events = []

    def record(stage, exc):
        events.append((stage, str(exc)))

    return events, record


def _intake_dependencies(*, result_put, record_suppressed):
    return InMemoryWorkerTaskIntakeDependencies(
        result_put=result_put,
        queue_empty_type=Empty,
        recoverable_exceptions=(RuntimeError, ValueError, TypeError, KeyError, AttributeError),
        record_suppressed=record_suppressed,
    )


def test_inmemory_worker_process_delegates_intake_submission_and_exit_publication():
    text = read_python_file(Path("Virus_Scan/scheduler/workers/inmemory_worker_process.py"))
    assert "task_q.get(" not in text
    assert "parse_inmemory_worker_task(" not in text
    assert "publish_inmemory_worker_assignment(" not in text
    assert "InMemoryWorkerJobExecutionRequest.build(" not in text
    assert "result_q.put(('worker_exit'" not in text
    assert "receive_inmemory_worker_task(" in text
    assert "submit_inmemory_worker_task(" in text
    assert "publish_inmemory_worker_exit(" in text


def test_worker_intake_returns_immutable_assignment_evidence():
    events, record = _recorded()
    result_q = _ResultQueue()
    intake = receive_inmemory_worker_task(
        task_q=_TaskQueue([(7, "a.bin", 2)]),
        intake=_intake_dependencies(result_put=result_q.put, record_suppressed=record),
    )
    assert isinstance(intake, InMemoryWorkerTaskIntakeResult)
    assert intake.task is not None
    assert intake.task.job_id == 7
    assert intake.assignment_published is True
    assert result_q.items[0][0] == "assigned"
    assert events == []
    try:
        intake.assignment_published = False
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("worker intake evidence must be immutable")


def test_worker_submission_returns_immutable_active_evidence():
    events, record = _recorded()
    result_q = _ResultQueue()
    intake = receive_inmemory_worker_task(
        task_q=_TaskQueue([(11, "b.bin", 4)]),
        intake=_intake_dependencies(result_put=result_q.put, record_suppressed=record),
    )
    active = {}
    result = submit_inmemory_worker_task(
        task=intake.task,
        tpool=_Pool(),
        active=active,
        execute_job=lambda request, deps: request,
        worker_execution_deps=object(),
        worker_config={},
        cancel_table={},
        heartbeat_table={},
        heartbeat_flags={},
        completed_jobs=0,
        recoverable_exceptions=(RuntimeError, ValueError, TypeError, KeyError, AttributeError),
        record_suppressed=record,
    )
    assert isinstance(result, InMemoryWorkerTaskSubmissionResult)
    assert result.submitted is True
    assert result.job_id == 11
    assert result.attempt == 4
    assert result.active_jobs == 1
    assert len(active) == 1
    try:
        result.active_jobs = 0
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("worker submission evidence must be immutable")


def test_worker_exit_publication_failure_is_evidence_not_clean_ack():
    events, record = _recorded()
    result = publish_inmemory_worker_exit(
        result_q=_ResultQueue(fail=True),
        worker_pid=123,
        timestamp=4.5,
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=record,
    )
    assert isinstance(result, InMemoryWorkerExitPublicationResult)
    assert result.worker_pid == 123
    assert result.published is False
    assert result.suppressed_failures == 1
    assert events and events[0][0] == "inmemory_worker_exit_publication_failure"


def test_worker_process_delegates_job_dependency_assembly_to_worker_contract():
    text = read_python_file(Path("Virus_Scan/scheduler/workers/inmemory_worker_process.py"))
    assert "InMemoryWorkerJobExecutionDependencies(" not in text
    assert "make_scheduler_cancel_result" not in text
    assert "execute_inmemory_scan_one_file" not in text
    assert "InMemoryWorkerThreadProgress" not in text
    assert "build_inmemory_worker_job_dependencies(" in text


def test_worker_job_dependency_assembly_returns_immutable_evidence():
    deps, evidence = build_inmemory_worker_job_dependencies(
        result_put=lambda _item: None,
        record_scheduler_suppressed=lambda _stage, _exc: None,
        recoverable_exceptions=(RuntimeError,),
    )
    assert deps.result_put is not None
    assert deps.worker_error_result is not None
    assert isinstance(evidence, InMemoryWorkerJobDependenciesEvidence)
    assert evidence.result_contract == "worker_error_result"
    try:
        evidence.result_contract = "mutated"
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("worker dependency evidence must be immutable")


def test_worker_bootstrap_failure_still_publishes_exit_evidence():
    context = multiprocessing.get_context("spawn")
    task_q = context.Queue()
    result_q = context.Queue()
    process = context.Process(
        target=run_inmemory_longlived_worker,
        args=(task_q, result_q, {}),
        name="umige-invalid-bootstrap-test",
    )
    process.start()
    process.join(timeout=20.0)
    try:
        assert process.is_alive() is False
        assert process.exitcode not in (None, 0)
        message = result_q.get(timeout=5.0)
        assert message[0] == "worker_exit"
        assert message[3] == process.pid
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=5.0)
        task_q.close()
        result_q.close()
        task_q.join_thread()
        result_q.join_thread()
