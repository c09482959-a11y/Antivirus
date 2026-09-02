"""Stage 1743: internal dataclass materializers reject spoofed module-owned classes."""

from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_materialize as contract_materialize
from Virus_Scan.contracts.work_stage import WorkStageCapacityClass as RealWorkStageCapacityClass
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_materialize as model_contract_materialize
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


class HostileDataDescriptor:
    touched = 0

    def __get__(self, _obj, _owner=None):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("spoofed internal dataclass descriptor must not execute")

    def __set__(self, obj, value):
        object.__setattr__(obj, "_payload", value)


def _spoofed_contract_dataclass_instance():
    @dataclass(frozen=True)
    class WorkStageCapacityClass:  # deliberately collides with real internal class name
        __module__ = "Virus_Scan.contracts.work_stage"
        payload: int = 1

    WorkStageCapacityClass.payload = HostileDataDescriptor()
    return WorkStageCapacityClass(7)


def _spoofed_scheduler_dataclass_instance():
    @dataclass(frozen=True)
    class SchedulerEvidenceRecord:  # deliberately collides with real scheduler class name
        __module__ = "Virus_Scan.scheduler.contracts.evidence_record"
        stage: str = "spoofed"

    SchedulerEvidenceRecord.stage = HostileDataDescriptor()
    return SchedulerEvidenceRecord("spoofed")


def test_stage1743_contract_no_hook_materializer_rejects_spoofed_internal_dataclass_without_descriptor_hook() -> None:
    HostileDataDescriptor.touched = 0
    result = contract_materialize(_spoofed_contract_dataclass_instance(), reason_prefix="stage1743")

    assert HostileDataDescriptor.touched == 0
    assert result["unavailable_reason"] == "non_materializable_stage1743_value"
    assert result["value_type"] == "WorkStageCapacityClass"


def test_stage1743_model_contract_no_hook_materializer_rejects_spoofed_internal_dataclass_without_descriptor_hook() -> None:
    HostileDataDescriptor.touched = 0
    result = model_contract_materialize(_spoofed_contract_dataclass_instance(), reason_prefix="stage1743")

    assert HostileDataDescriptor.touched == 0
    assert result["unavailable_reason"] == "non_materializable_stage1743_value"
    assert result["value_type"] == "WorkStageCapacityClass"


def test_stage1743_scheduler_materializer_rejects_spoofed_internal_dataclass_without_descriptor_hook() -> None:
    HostileDataDescriptor.touched = 0
    result = materialize_scheduler_mapping(_spoofed_scheduler_dataclass_instance())

    assert HostileDataDescriptor.touched == 0
    assert result["unsupported_scheduler_value"] is True
    assert result["error_category"] == "scheduler_json_materialization_unsupported"
    assert result["value_type"] == "SchedulerEvidenceRecord"


def test_stage1743_loaded_internal_dataclasses_still_materialize() -> None:
    capacity = RealWorkStageCapacityClass("stage1743", 3, 2.5)
    assert contract_materialize(capacity, reason_prefix="stage1743") == {
        "default_limit": 3,
        "name": "stage1743",
        "weight": 2.5,
    }
    assert model_contract_materialize(capacity, reason_prefix="stage1743") == {
        "default_limit": 3,
        "name": "stage1743",
        "weight": 2.5,
    }

    scheduler_record = SchedulerEvidenceRecord(stage="stage1743", error_category="spoof_boundary")
    scheduler_json = materialize_scheduler_mapping(scheduler_record)
    assert scheduler_json["stage"] == "stage1743"
    assert scheduler_json["error_category"] == "spoof_boundary"
