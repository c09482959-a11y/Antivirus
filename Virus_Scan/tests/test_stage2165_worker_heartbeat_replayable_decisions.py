from __future__ import annotations

from Virus_Scan.scheduler.workers.heartbeat_support import heartbeat_stage_code, heartbeat_stage_code_decision
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_cycle import (
    heartbeat_active_items_decision,
    heartbeat_cfg_decision,
)


class HostileScalar:
    def __init__(self) -> None:
        self.touched = False

    def __str__(self) -> str:  # pragma: no cover - must not be invoked
        self.touched = True
        raise AssertionError("__str__ must not be invoked")

    def __repr__(self) -> str:  # pragma: no cover - must not be invoked
        self.touched = True
        raise AssertionError("__repr__ must not be invoked")

    def __bool__(self) -> bool:  # pragma: no cover - must not be invoked
        self.touched = True
        raise AssertionError("__bool__ must not be invoked")


class HostileMappingLike(HostileScalar):
    def items(self):  # pragma: no cover - must not be invoked
        self.touched = True
        raise AssertionError("items must not be invoked")

    def __iter__(self):  # pragma: no cover - must not be invoked
        self.touched = True
        raise AssertionError("__iter__ must not be invoked")



def test_worker_heartbeat_active_items_decision_records_non_mapping_without_hooks() -> None:
    hostile = HostileMappingLike()

    decision = heartbeat_active_items_decision(hostile)

    assert decision.accepted is False
    assert decision.reason == "worker_heartbeat_active_not_mapping"
    assert decision.items == ()
    assert decision.evidence
    assert decision.evidence[0]["worker_heartbeat_mapping_failure"] == "worker_heartbeat_active_not_mapping"
    assert decision.evidence[0]["replay_must_record"] is True
    assert hostile.touched is False



def test_worker_heartbeat_cfg_decision_records_non_mapping_and_preserves_legacy_projection() -> None:
    hostile = HostileMappingLike()

    decision = heartbeat_cfg_decision(hostile)

    assert decision.accepted is False
    assert decision.reason == "worker_heartbeat_config_not_mapping"
    assert dict(decision.config) == {}
    assert decision.evidence[0]["field"] == "heartbeat_config"
    assert decision.evidence[0]["checkpoint_must_record"] is True
    assert hostile.touched is False



def test_heartbeat_stage_code_decision_distinguishes_rejected_and_unknown_without_hooks() -> None:
    hostile = HostileScalar()

    rejected = heartbeat_stage_code_decision(hostile)
    unknown = heartbeat_stage_code_decision("not-a-known-stage")
    scan = heartbeat_stage_code_decision("scan")

    assert rejected.accepted is False
    assert rejected.reason == "heartbeat_stage_rejected"
    assert rejected.stage_code == heartbeat_stage_code(hostile) == 0
    assert hostile.touched is False
    assert unknown.accepted is False
    assert unknown.reason == "heartbeat_stage_unknown"
    assert unknown.stage_code == 0
    assert scan.accepted is True
    assert scan.stage_code == 3
    assert scan.stage_name == "scan"
