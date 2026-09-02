from __future__ import annotations

from Virus_Scan.scheduler.workers.inmemory_capacity_plan import build_inmemory_capacity_plan


class HostileEnvValue:
    touched = 0

    def __str__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("do not stringify env value")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("do not repr env value")

    def __float__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("do not float env value")

    def __int__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("do not int env value")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("do not truth-test env value")


def test_stage1639_capacity_plan_rejects_hostile_environment_values_without_hooks():
    HostileEnvValue.touched = 0
    plan = build_inmemory_capacity_plan(
        {
            "UMIGE_INMEMORY_QUEUE_DEPTH": HostileEnvValue(),
            "UMIGE_INMEMORY_MAX_INFLIGHT_MULT": HostileEnvValue(),
            "UMIGE_INMEMORY_MAX_QUEUED_UNSTARTED": HostileEnvValue(),
        },
        workers=2,
        worker_threads=3,
    )

    assert plan.logical_slots == 6
    assert plan.queue_depth == 48
    assert plan.max_inflight == 7
    assert plan.max_queued_unstarted == 4
    assert HostileEnvValue.touched == 0


def test_stage1639_capacity_plan_preserves_exact_environment_strings():
    plan = build_inmemory_capacity_plan(
        {
            "UMIGE_INMEMORY_QUEUE_DEPTH": "128",
            "UMIGE_INMEMORY_MAX_INFLIGHT_MULT": "2.0",
            "UMIGE_INMEMORY_MAX_QUEUED_UNSTARTED": "33",
        },
        workers=2,
        worker_threads=3,
    )

    assert plan.logical_slots == 6
    assert plan.queue_depth == 128
    assert plan.max_inflight == 12
    assert plan.max_queued_unstarted == 33
