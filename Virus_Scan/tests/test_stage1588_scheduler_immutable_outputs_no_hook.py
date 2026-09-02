from __future__ import annotations

from Virus_Scan.scheduler.evidence.final_json_contract_support import _mapping_materialization_failure
from Virus_Scan.scheduler.internal.immutable_outputs import (
    immutable_mapping,
    immutable_value,
    materialize_scheduler_mapping,
)


class HostileSchedulerMeta(type):
    touched = 0

    def __getattribute__(cls, name):  # pragma: no cover - test fails if touched
        if name in {"__dataclass_params__", "__module__"}:
            HostileSchedulerMeta.touched += 1
            raise RuntimeError("scheduler boundary touched hostile metaclass")
        return super().__getattribute__(name)


class HostileSchedulerValue(metaclass=HostileSchedulerMeta):
    def __str__(self):  # pragma: no cover - test fails if touched
        raise RuntimeError("do not stringify scheduler value")

    def __repr__(self):  # pragma: no cover - test fails if touched
        raise RuntimeError("do not repr scheduler value")


class HostileSchedulerException(Exception):
    touched = 0

    def __str__(self):  # pragma: no cover - test fails if touched
        type(self).touched += 1
        raise RuntimeError("do not stringify scheduler exception")


def test_stage1588_immutable_value_rejects_unknown_object_before_boundary_crossing():
    HostileSchedulerMeta.touched = 0
    value = immutable_value(HostileSchedulerValue())

    assert HostileSchedulerMeta.touched == 0
    assert value["status"] == "failed"
    assert value["unsupported_scheduler_value"] is True
    assert value["error_category"] == "scheduler_json_materialization_unsupported"
    assert value["final_json_must_record"] is True
    assert value["checkpoint_must_record"] is True
    assert value["replay_must_record"] is True
    assert value["value_type"] == "HostileSchedulerValue"


def test_stage1588_materialize_scheduler_mapping_rejects_unknown_without_metaclass_hooks():
    HostileSchedulerMeta.touched = 0
    value = materialize_scheduler_mapping(HostileSchedulerValue())

    assert HostileSchedulerMeta.touched == 0
    assert value["status"] == "failed"
    assert value["unsupported_scheduler_value"] is True
    assert value["value_type"] == "HostileSchedulerValue"


def test_stage1588_immutable_mapping_replaces_unknown_nested_value_before_boundary_crossing():
    HostileSchedulerMeta.touched = 0
    frozen = immutable_mapping({"hostile": HostileSchedulerValue()})
    materialized = materialize_scheduler_mapping(frozen)

    assert HostileSchedulerMeta.touched == 0
    assert materialized["hostile"]["status"] == "failed"
    assert materialized["hostile"]["unsupported_scheduler_value"] is True


def test_stage1588_scheduler_materialization_failure_helper_does_not_stringify_exception():
    HostileSchedulerException.touched = 0
    evidence = _mapping_materialization_failure(HostileSchedulerValue(), HostileSchedulerException())

    assert HostileSchedulerException.touched == 0
    assert evidence["status"] == "failed"
    assert evidence["error_category"] == "scheduler_mapping_materialization_failed"
    assert evidence["exception_type"] == "HostileSchedulerException"
    assert evidence["message"] == "scheduler mapping materialization failed"
    assert evidence["final_json_must_record"] is True
