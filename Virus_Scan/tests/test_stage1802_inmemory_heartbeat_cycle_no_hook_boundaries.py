from __future__ import annotations

from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_cycle import publish_inmemory_worker_heartbeat_cycle


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    items_calls = 0
    getattribute_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0
        cls.items_calls = 0
        cls.getattribute_calls = 0

    def __getattribute__(self, name):
        if name == "__class__":
            type(self).getattribute_calls += 1
            raise AssertionError("__class__ hook must not execute")
        return object.__getattribute__(self, name)

    def __str__(self):
        type(self).str_calls += 1
        raise AssertionError("__str__ hook must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise AssertionError("__repr__ hook must not execute")

    def __format__(self, _spec):
        type(self).format_calls += 1
        raise AssertionError("__format__ hook must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise AssertionError("__bool__ hook must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise AssertionError("__iter__ hook must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise AssertionError("__float__ hook must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise AssertionError("__int__ hook must not execute")

    def items(self):
        type(self).items_calls += 1
        raise AssertionError("items hook must not execute")


class HeartbeatFlags:
    running = 1
    cancel_request = 2
    poisoned_or_retire_mask = 4


def _assert_no_hostile_hooks() -> None:
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.items_calls == 0
    assert HostileValue.getattribute_calls == 0


def test_stage1802_heartbeat_cycle_rejects_hostile_inactive_inputs_without_hooks():
    HostileValue.reset()
    calls: list[object] = []

    result = publish_inmemory_worker_heartbeat_cycle(
        active=HostileValue(),
        cfg=HostileValue(),
        cancel_table=None,
        heartbeat_table=None,
        heartbeat_flags=HostileValue(),
        completed_jobs=HostileValue(),
        cancel_requested=lambda *_args, **_kwargs: False,
        update_shared_heartbeat=lambda *args, **_kwargs: calls.append(args),
        process_id=HostileValue(),
        now_hb=HostileValue(),
        last_heartbeat_emit=HostileValue(),
        heartbeat_interval=HostileValue(),
        heartbeat_seq=HostileValue(),
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda *_args, **_kwargs: None,
    )

    assert result.last_heartbeat_emit == 0.0
    assert result.heartbeat_seq == 0
    assert result.stop_requested is False
    assert result.heartbeat_published is False
    assert result.heartbeat_failure_count == 0
    assert calls == []
    _assert_no_hostile_hooks()


def test_stage1802_heartbeat_cycle_publishes_exact_active_mapping_with_hostile_scalars_without_hooks():
    HostileValue.reset()
    meta = {
        "job_id": "job-1",
        "attempt": HostileValue(),
        "stage": "scan",
        "progress_counter": 3,
        "bytes_processed": HostileValue(),
        "last_progress_ns": HostileValue(),
    }
    updates: list[dict[str, object]] = []

    def update_shared_heartbeat(*_args, **kwargs):
        updates.append(kwargs)
        return HostileValue()

    result = publish_inmemory_worker_heartbeat_cycle(
        active={object(): meta},
        cfg=HostileValue(),
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=HeartbeatFlags(),
        completed_jobs=HostileValue(),
        cancel_requested=lambda *_args, **_kwargs: HostileValue(),
        update_shared_heartbeat=update_shared_heartbeat,
        process_id=HostileValue(),
        now_hb=5.0,
        last_heartbeat_emit=0.0,
        heartbeat_interval=1.0,
        heartbeat_seq=HostileValue(),
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda *_args, **_kwargs: None,
    )

    assert result.last_heartbeat_emit == 5.0
    assert result.heartbeat_seq == 1
    assert result.stop_requested is False
    assert result.heartbeat_published is False
    assert result.heartbeat_failure_count == 1
    assert updates[0]["progress_counter"] == 3
    assert updates[0]["bytes_processed"] == 0
    assert updates[0]["completed_jobs"] == 0
    assert updates[0]["pid"] == 0
    assert result.heartbeat_failure_evidence[0]["worker_heartbeat_publish_failed"] is True
    _assert_no_hostile_hooks()


def test_stage1802_heartbeat_cycle_failure_evidence_does_not_materialize_hostile_mapping():
    HostileValue.reset()
    meta = {
        "job_id": "job-2",
        "attempt": 1,
        "stage": "scan",
        "progress_counter": 1,
        "heartbeat_publish_failed": True,
        "heartbeat_publish_evidence": HostileValue(),
    }

    result = publish_inmemory_worker_heartbeat_cycle(
        active={object(): meta},
        cfg={},
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=HeartbeatFlags(),
        completed_jobs=0,
        cancel_requested=lambda *_args, **_kwargs: False,
        update_shared_heartbeat=lambda *_args, **_kwargs: False,
        process_id=4321,
        now_hb=10.0,
        last_heartbeat_emit=1.0,
        heartbeat_interval=1.0,
        heartbeat_seq=2,
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda *_args, **_kwargs: None,
    )

    assert result.heartbeat_published is False
    assert result.heartbeat_failure_count == 1
    assert result.heartbeat_failure_evidence[0]["worker_heartbeat_publish_failed"] is True
    _assert_no_hostile_hooks()
