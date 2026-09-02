from __future__ import annotations

import contextvars
import threading

import pytest

from Virus_Scan.scheduler.api.thread_lifecycle import SchedulerThreadPool


class HostileSchedulerPoolValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")

    def __format__(self, _format_spec):
        type(self).touched += 1
        raise RuntimeError("do not call format")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not call int")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not call float")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not call iter")


@pytest.mark.parametrize("field", ["max_workers", "thread_name_prefix", "cancel_on_error"])
def test_scheduler_thread_pool_rejects_hostile_constructor_values_without_hooks(field: str) -> None:
    HostileSchedulerPoolValue.reset()
    kwargs = {"max_workers": 1, "thread_name_prefix": "umige-test", "cancel_on_error": True}
    kwargs[field] = HostileSchedulerPoolValue()

    with pytest.raises(TypeError):
        SchedulerThreadPool(**kwargs)

    assert HostileSchedulerPoolValue.touched == 0


def test_scheduler_thread_pool_preserves_exact_primitive_constructor_values() -> None:
    pool = SchedulerThreadPool(max_workers="3", thread_name_prefix="umige-test", cancel_on_error="false")

    assert pool.max_workers == 3
    assert pool.thread_name_prefix == "umige-test"
    assert pool.cancel_on_error is False


def test_scheduler_thread_pool_rejects_non_integral_text_worker_count_without_hostile_hooks() -> None:
    with pytest.raises(ValueError):
        SchedulerThreadPool(max_workers="many", thread_name_prefix="umige-test", cancel_on_error=True)


def test_scheduler_thread_pool_rejects_non_integral_float_worker_count() -> None:
    with pytest.raises(ValueError, match="exact integer"):
        SchedulerThreadPool(max_workers=2.9, thread_name_prefix="umige-test", cancel_on_error=True)


def test_scheduler_thread_pool_accepts_integral_float_worker_count() -> None:
    pool = SchedulerThreadPool(max_workers=2.0, thread_name_prefix="umige-test", cancel_on_error=True)

    assert pool.max_workers == 2


def test_scheduler_thread_pool_reuses_after_context_exit() -> None:
    pool = SchedulerThreadPool(max_workers=1, thread_name_prefix="umige-reuse", cancel_on_error=True)

    with pool as active:
        assert active.submit(lambda: "first").result(timeout=2) == "first"

    with pool as active:
        assert active.submit(lambda: "second").result(timeout=2) == "second"

    with pytest.raises(RuntimeError, match="not active"):
        pool.submit(lambda: "closed")


def test_scheduler_thread_pool_rejects_nested_active_reentry() -> None:
    pool = SchedulerThreadPool(max_workers=1, thread_name_prefix="umige-reentry", cancel_on_error=True)

    with pool:
        with pytest.raises(RuntimeError, match="already active"):
            pool.__enter__()


def test_scheduler_thread_pool_propagates_contextvars_to_submitted_work() -> None:
    request_id = contextvars.ContextVar("scheduler_thread_pool_request_id")
    request_id.set("ctx-1655")

    with SchedulerThreadPool(max_workers=1, thread_name_prefix="umige-context", cancel_on_error=True) as pool:
        assert pool.submit(request_id.get).result(timeout=2) == "ctx-1655"


def test_scheduler_thread_pool_cleans_future_after_consumer_exception() -> None:
    def fail() -> None:
        raise ValueError("consumer failed")

    with SchedulerThreadPool(max_workers=1, thread_name_prefix="umige-exc", cancel_on_error=True) as pool:
        future = pool.submit(fail)
        with pytest.raises(ValueError, match="consumer failed"):
            future.result(timeout=2)
        assert future.done()
        assert list(pool._futures) == []


def test_scheduler_thread_pool_cancel_pending_cancels_queued_work_and_shutdown_cleans_state() -> None:
    gate = threading.Event()
    started = threading.Event()

    def wait_for_release() -> str:
        started.set()
        gate.wait(timeout=2)
        return "released"

    def queued() -> str:
        return "queued"

    pool = SchedulerThreadPool(max_workers=1, thread_name_prefix="umige-cancel", cancel_on_error=True)
    with pool as active:
        running = active.submit(wait_for_release)
        assert started.wait(timeout=2)
        pending = active.submit(queued)

        assert active.cancel_pending() == 1
        assert pending.cancelled()
        gate.set()
        assert running.result(timeout=2) == "released"

    assert pool._executor is None
    assert list(pool._futures) == []
    with pytest.raises(RuntimeError, match="not active"):
        pool.submit(queued)
