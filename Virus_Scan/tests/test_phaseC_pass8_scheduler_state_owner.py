from types import MappingProxyType

from Virus_Scan.runtime.scheduler_state import (
    SchedulerStateOwner,
    publish_workload_queue_plan,
)
from Virus_Scan.runtime.ownership import RuntimeStateOwner


def test_scheduler_workload_plan_owner_snapshots_without_shared_state_mutation():
    plan = {"limits": {"raw": 4}, "counts": {"raw": 2}}
    owner = SchedulerStateOwner()
    snap = owner.publish_workload_plan(plan)
    assert isinstance(snap, MappingProxyType)
    plan["limits"]["raw"] = 99
    stored = owner.workload_plan()
    assert stored["limits"]["raw"] == 4
    assert owner.snapshot()["UMIGE_WORKLOAD_QUEUE_PLAN"]["counts"]["raw"] == 2


def test_scheduler_workload_plan_public_publisher_returns_frozen_plan():
    plan = {"limits": {"raw": 4}, "counts": {"raw": 2}}
    snap = publish_workload_queue_plan(plan)
    assert isinstance(snap, MappingProxyType)
    plan["limits"]["raw"] = 99
    assert snap["limits"]["raw"] == 4


def test_runtime_state_owner_no_longer_defaults_to_legacy_shared_state():
    owner = RuntimeStateOwner()
    owner.set("phase_c_owner", "direct", domain="runtime")
    assert owner.readonly_view().get("phase_c_owner") == "direct"
    assert "phase_c_owner" in owner.snapshot()
