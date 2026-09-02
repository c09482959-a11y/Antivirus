from Virus_Scan.scheduler.workers.lifecycle_boundary import SchedulerIsolationBoundary, WorkerLifecycleEvent


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0

    @classmethod
    def reset(cls):
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("must not execute")


class HostileMapping(dict):
    items_calls = 0

    def items(self):
        type(self).items_calls += 1
        raise RuntimeError("must not execute")


def _assert_no_hostile_hooks():
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0


def test_stage1788_worker_lifecycle_event_rejects_hostile_fields_without_hooks():
    HostileValue.reset()
    boundary = SchedulerIsolationBoundary(scheduler_id=HostileValue())
    result = boundary.transition(WorkerLifecycleEvent(HostileValue(), HostileValue(), "new", "queued", HostileValue(), HostileValue()))
    assert result["status"] == "rejected"
    assert result["scheduler_id"] == "scheduler"
    assert result["input_rejections"]
    assert any(item["field_name"] == "worker_id" for item in result["input_rejections"])
    _assert_no_hostile_hooks()


def test_stage1788_worker_lifecycle_mapping_rejects_hostile_mapping_without_items():
    HostileValue.reset()
    HostileMapping.items_calls = 0
    boundary = SchedulerIsolationBoundary(scheduler_id="stage1788")
    result = boundary.transition(HostileMapping({"queue_id": "q"}))
    assert result["status"] == "rejected"
    assert result["input_rejections"]
    assert HostileMapping.items_calls == 0
    _assert_no_hostile_hooks()


def test_stage1788_worker_lifecycle_preserves_valid_exact_primitives():
    boundary = SchedulerIsolationBoundary(scheduler_id="stage1788")
    first = boundary.transition(WorkerLifecycleEvent("w1", "q1", "new", "queued", "claim", "2"))
    assert first["event"]["retry_generation"] == 2
    assert first["event"]["reason"] == "claim"
    second = boundary.transition({"worker_id": "w1", "queue_id": "q1", "from_state": "queued", "to_state": "claimed"})
    assert second["event"]["queue_id"] == "q1"
    assert boundary.state_of("q1") == "claimed"
