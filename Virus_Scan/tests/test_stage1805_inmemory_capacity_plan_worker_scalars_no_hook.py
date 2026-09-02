from __future__ import annotations

from Virus_Scan.scheduler.workers.inmemory_capacity_plan import build_inmemory_capacity_plan


class HostileWorkerScalar:
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

    @classmethod
    def total_calls(cls) -> int:
        return (
            cls.str_calls
            + cls.repr_calls
            + cls.format_calls
            + cls.bool_calls
            + cls.iter_calls
            + cls.float_calls
            + cls.int_calls
            + cls.getattribute_calls
        )

    def __getattribute__(self, name: str):  # pragma: no cover - must never execute
        type(self).getattribute_calls += 1
        raise RuntimeError(f"worker scalar attribute access is forbidden: {name}")

    def __str__(self):  # pragma: no cover - must never execute
        type(self).str_calls += 1
        raise RuntimeError("worker scalar stringification is forbidden")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).repr_calls += 1
        raise RuntimeError("worker scalar repr is forbidden")

    def __format__(self, spec):  # pragma: no cover - must never execute
        type(self).format_calls += 1
        raise RuntimeError("worker scalar formatting is forbidden")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).bool_calls += 1
        raise RuntimeError("worker scalar truth testing is forbidden")

    def __iter__(self):  # pragma: no cover - must never execute
        type(self).iter_calls += 1
        raise RuntimeError("worker scalar iteration is forbidden")

    def __float__(self):  # pragma: no cover - must never execute
        type(self).float_calls += 1
        raise RuntimeError("worker scalar float conversion is forbidden")

    def __int__(self):  # pragma: no cover - must never execute
        type(self).int_calls += 1
        raise RuntimeError("worker scalar int conversion is forbidden")


def test_stage1805_capacity_plan_rejects_hostile_worker_scalars_without_hooks():
    HostileWorkerScalar.reset()

    plan = build_inmemory_capacity_plan(
        {},
        workers=HostileWorkerScalar(),
        worker_threads=HostileWorkerScalar(),
    )

    assert plan.logical_slots == 1
    assert plan.queue_depth == 8
    assert plan.max_inflight == 1
    assert plan.max_queued_unstarted == 2
    assert HostileWorkerScalar.total_calls() == 0


def test_stage1805_capacity_plan_preserves_exact_worker_scalar_text():
    plan = build_inmemory_capacity_plan(
        {},
        workers="4",
        worker_threads="2",
    )

    assert plan.logical_slots == 8
    assert plan.queue_depth == 64
    assert plan.max_inflight == 9
    assert plan.max_queued_unstarted == 8
