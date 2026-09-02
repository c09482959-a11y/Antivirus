from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from dataclasses import dataclass
from pathlib import Path

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.internal.immutable_output_support import (
    FrozenSchedulerMapping,
    _materialize_scheduler_key,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.immutable_dataclass_ownership import (
    _internal_frozen_dataclass_decision,
    _loaded_scheduler_dataclass_type_decision,
)
from Virus_Scan.scheduler.internal.immutable_snapshots import immutable_snapshot_mapping


class HostileImmutableValue:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("immutable scheduler projection called __str__")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("immutable scheduler projection called __repr__")

    def __format__(self, _spec):
        type(self).touched += 1
        raise AssertionError("immutable scheduler projection called __format__")

    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("immutable scheduler projection called __iter__")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("immutable scheduler projection called __bool__")


class HostileDescriptor:
    touched = 0

    def __get__(self, _obj, _owner=None):
        type(self).touched += 1
        raise AssertionError("spoofed scheduler dataclass descriptor executed")

    def __set__(self, obj, value):
        object.__setattr__(obj, "_payload", value)


def _spoofed_scheduler_record() -> object:
    @dataclass(frozen=True)
    class SchedulerEvidenceRecord:
        __module__ = "Virus_Scan.scheduler.contracts.evidence_record"
        stage: str = "spoofed"

    SchedulerEvidenceRecord.stage = HostileDescriptor()
    return SchedulerEvidenceRecord("spoofed")


def test_stage1854_scheduler_dataclass_spoof_rejection_does_not_use_false_sentinels_or_hooks() -> None:
    HostileDescriptor.touched = 0

    projected = materialize_scheduler_mapping(_spoofed_scheduler_record())

    assert HostileDescriptor.touched == 0
    assert projected["unsupported_scheduler_value"] is True
    assert projected["value_type"] == "SchedulerEvidenceRecord"


def test_stage1854_real_scheduler_dataclass_still_materializes() -> None:
    record = SchedulerEvidenceRecord(stage="stage1854", error_category="immutable_projection")

    projected = materialize_scheduler_mapping(record)

    assert projected["stage"] == "stage1854"
    assert projected["error_category"] == "immutable_projection"


def test_stage1854_frozen_mapping_invalid_item_key_is_owned_without_hooks() -> None:
    hostile = HostileImmutableValue()
    HostileImmutableValue.touched = 0

    frozen = FrozenSchedulerMapping((("safe", 1), hostile))  # type: ignore[arg-type]
    projected = materialize_scheduler_mapping(frozen)

    assert HostileImmutableValue.touched == 0
    assert projected["safe"] == 1
    assert projected["unsupported_scheduler_item_1"]["unsupported_scheduler_value"] is True
    assert projected["unsupported_scheduler_item_1"]["field_name"] == "unsupported_scheduler_item_1"


def test_stage1854_frozen_mapping_repr_and_unsupported_key_are_owned_text() -> None:
    hostile = HostileImmutableValue()
    HostileImmutableValue.touched = 0

    frozen = FrozenSchedulerMapping((("safe", 1),))
    key = _materialize_scheduler_key(hostile, 7)

    assert HostileImmutableValue.touched == 0
    assert repr(frozen) == "FrozenSchedulerMapping(size=1)"
    assert key == "unsupported_scheduler_key_7"


def test_stage1854_immutable_snapshot_exact_dict_freeze_does_not_call_value_hooks() -> None:
    hostile = HostileImmutableValue()
    HostileImmutableValue.touched = 0

    snapshot = immutable_snapshot_mapping({"bad": hostile}, field_name="stage1854_snapshot")
    projected = materialize_scheduler_mapping(snapshot)

    assert HostileImmutableValue.touched == 0
    assert projected["bad"]["unsupported_scheduler_value"] is True



def test_stage2185_scheduler_dataclass_ownership_uses_replayable_decisions() -> None:
    record = SchedulerEvidenceRecord(stage="stage2185", error_category="ownership_decision")

    type_decision = _loaded_scheduler_dataclass_type_decision(record)
    frozen_decision = _internal_frozen_dataclass_decision(record)
    spoof_type_decision = _loaded_scheduler_dataclass_type_decision(_spoofed_scheduler_record())

    assert type_decision.accepted is True
    assert type_decision.reason == "scheduler_dataclass_type_loaded_owner"
    assert frozen_decision.accepted is True
    assert frozen_decision.reason == "scheduler_frozen_dataclass_accepted"
    assert spoof_type_decision.accepted is False
    assert spoof_type_decision.reason == "scheduler_dataclass_type_not_loaded_owner"

def test_stage1854_static_guards_close_immutable_projection_rows() -> None:
    dataclass_source = read_python_file(Path("Virus_Scan/scheduler/internal/immutable_dataclass_ownership.py"))
    support_source = read_python_file(Path("Virus_Scan/scheduler/internal/immutable_output_support.py"))
    snapshot_source = read_python_file(Path("Virus_Scan/scheduler/internal/immutable_snapshots.py"))

    assert "return False" not in dataclass_source
    assert 'f"unsupported_scheduler_item_{index}"' not in support_source
    assert 'field_name=f"unsupported_scheduler_item_{index}"' not in support_source
    assert 'return f"FrozenSchedulerMapping(size={len(self._items)})"' not in support_source
    assert 'return f"unsupported_scheduler_key_{index}"' not in support_source
    assert "dict.items(value)" not in snapshot_source
