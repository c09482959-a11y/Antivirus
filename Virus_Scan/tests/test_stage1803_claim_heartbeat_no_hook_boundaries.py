from __future__ import annotations

from Virus_Scan.scheduler.workers.claim_heartbeat import start_worker_claim_heartbeat, stop_worker_claim_heartbeat


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
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


class HostileHandle:
    touched = 0

    def __getattribute__(self, name):
        if name in {"stop_event", "thread"}:
            type(self).touched += 1
            raise AssertionError("handle fields must not be read")
        return object.__getattribute__(self, name)


def _assert_no_hostile_hooks() -> None:
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.getattribute_calls == 0


def test_stage1803_claim_heartbeat_rejects_hostile_worker_and_interval_without_hooks():
    HostileValue.reset()
    seen: list[tuple[object, object]] = []

    handle = start_worker_claim_heartbeat(
        "claim.json",
        job=HostileValue(),
        worker_id=HostileValue(),
        interval_sec=HostileValue(),
        update_callback=lambda _path, *, job, worker_id: seen.append((job, worker_id)) or True,
    )

    assert handle.worker_id == "worker"
    assert handle.interval_sec == 5.0
    assert seen == [(seen[0][0], "worker")]
    assert stop_worker_claim_heartbeat(handle, timeout_sec=HostileValue()) is True
    _assert_no_hostile_hooks()


def test_stage1803_stop_claim_heartbeat_rejects_hostile_handle_without_descriptors():
    HostileValue.reset()
    HostileHandle.touched = 0

    assert stop_worker_claim_heartbeat(HostileHandle(), timeout_sec=HostileValue()) is False

    assert HostileHandle.touched == 0
    _assert_no_hostile_hooks()
