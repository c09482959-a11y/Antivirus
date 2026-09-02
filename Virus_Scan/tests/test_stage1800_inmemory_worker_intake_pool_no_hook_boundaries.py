from queue import Empty

from Virus_Scan.scheduler.workers.inmemory_worker_assignment import (
    InMemoryAssignedTask,
    make_inmemory_worker_task_meta,
    parse_inmemory_worker_task,
    publish_inmemory_worker_assignment,
)
from Virus_Scan.scheduler.workers.inmemory_worker_intake import (
    InMemoryWorkerTaskIntakeDependencies,
    receive_inmemory_worker_task,
)
from Virus_Scan.scheduler.workers.inmemory_worker_pool import InMemoryWorkerPoolStartupResult, start_inmemory_worker_pool


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    class_getattribute_calls = 0

    @classmethod
    def reset(cls):
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0
        cls.class_getattribute_calls = 0

    def __getattribute__(self, name):
        if name == "__class__":
            type(self).class_getattribute_calls += 1
            raise RuntimeError("must not execute class lookup")
        return object.__getattribute__(self, name)

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute str")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute repr")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute format")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute bool")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not execute iter")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("must not execute float")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("must not execute int")


class FakeTaskQueue:
    def __init__(self, item=None, *, empty=False):
        self.item = item
        self.empty = empty
        self.timeouts = []

    def get(self, timeout=0.0):
        self.timeouts.append(timeout)
        if self.empty:
            raise Empty()
        return self.item


def _intake_dependencies(*, result_put, record_suppressed):
    return InMemoryWorkerTaskIntakeDependencies(
        result_put=result_put,
        queue_empty_type=Empty,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError),
        record_suppressed=record_suppressed,
    )


class FakeProcess:
    def __init__(self, *, target, args, name):
        self.target = target
        self.args = args
        self.name = name
        self.daemon = None
        self.started = False

    def start(self):
        self.started = True


class FakeContext:
    def __init__(self):
        self.processes = []

    def Process(self, *, target, args, name):
        process = FakeProcess(target=target, args=args, name=name)
        self.processes.append(process)
        return process


def assert_hostile_untouched():
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.class_getattribute_calls == 0


def test_stage1800_intake_timeout_rejects_hostile_float_without_hooks():
    HostileValue.reset()
    task_q = FakeTaskQueue(empty=True)
    result = receive_inmemory_worker_task(
        task_q=task_q,
        intake=_intake_dependencies(
            result_put=lambda _item: None,
            record_suppressed=lambda _stage, _exc: None,
        ),
        timeout_sec=HostileValue(),
    )

    assert result.queue_empty is True
    assert task_q.timeouts == [0.05]
    assert_hostile_untouched()


def test_stage1800_invalid_assignment_rejects_hostile_item_without_preview_hooks():
    HostileValue.reset()
    events = []
    result = receive_inmemory_worker_task(
        task_q=FakeTaskQueue(HostileValue()),
        intake=_intake_dependencies(
            result_put=lambda _item: None,
            record_suppressed=lambda stage, exc: events.append((stage, type(exc).__name__)),
        ),
    )

    assert result.invalid_assignment is True
    assert events == [("inmemory_worker_invalid_assignment", "RuntimeError")]
    assert_hostile_untouched()


def test_stage1800_assignment_attempt_rejects_hostile_scalar_without_hooks():
    HostileValue.reset()
    result_items = []
    result = receive_inmemory_worker_task(
        task_q=FakeTaskQueue(("job-1", "path.bin", HostileValue())),
        intake=_intake_dependencies(
            result_put=result_items.append,
            record_suppressed=lambda _stage, _exc: None,
        ),
    )

    assert result.task is not None
    assert result.task.attempt == 0
    assert result.assignment_published is True
    assert result_items[0][5] == 0
    assert_hostile_untouched()


def test_stage1800_assignment_helpers_reject_hostile_attempt_without_hooks():
    HostileValue.reset()
    task = InMemoryAssignedTask(job_id="job-2", path="x.bin", attempt=HostileValue())
    parsed = parse_inmemory_worker_task(
        ["job-3", "y.bin", HostileValue()],
        recoverable_exceptions=(RuntimeError, TypeError, ValueError),
    )
    meta = make_inmemory_worker_task_meta(task)
    published = publish_inmemory_worker_assignment(
        result_put=lambda _item: (_ for _ in ()).throw(RuntimeError("queue down")),
        task=task,
        record_scheduler_suppressed=lambda _stage, _exc: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError),
    )

    assert parsed is not None
    assert parsed.attempt == 0
    assert meta["attempt"] == 0
    assert published.attempt == 0
    assert published.published is False
    assert_hostile_untouched()


def test_stage1800_worker_pool_startup_rejects_hostile_processes_without_iteration():
    HostileValue.reset()
    result = InMemoryWorkerPoolStartupResult(processes=HostileValue(), started=0)

    assert result.processes == ()
    assert_hostile_untouched()


def test_stage1800_worker_pool_rejects_hostile_count_and_prefix_without_hooks():
    HostileValue.reset()
    context = FakeContext()
    result = start_inmemory_worker_pool(
        context=context,
        worker_count=HostileValue(),
        task_queue=object(),
        result_queue=object(),
        worker_config={},
        name_prefix=HostileValue(),
    )

    assert result.started == 0
    assert context.processes == []
    assert_hostile_untouched()


def test_stage1800_worker_pool_uses_safe_fallback_prefix_for_hostile_prefix():
    HostileValue.reset()
    context = FakeContext()
    result = start_inmemory_worker_pool(
        context=context,
        worker_count=1,
        task_queue=object(),
        result_queue=object(),
        worker_config={},
        name_prefix=HostileValue(),
    )

    assert result.started == 1
    assert context.processes[0].name == "umige-inmem-000"
    assert context.processes[0].started is True
    assert_hostile_untouched()
