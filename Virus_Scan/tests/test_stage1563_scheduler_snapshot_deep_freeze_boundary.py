"""Stage1563 Phase 2 scheduler immutable snapshot/deep-freeze boundary tests."""
from __future__ import annotations

import gc
from types import MappingProxyType

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.contracts.replay_result import ReplaySnapshot
from Virus_Scan.scheduler.evidence.final_json_exact_fields import exact_mapping_items
from Virus_Scan.scheduler.internal.immutable_outputs import (
    FrozenSchedulerMapping,
    materialize_scheduler_mapping,
)
from Virus_Scan.scheduler.internal.immutable_snapshots import immutable_snapshot_mapping


class HostileValue:
    str_calls = 0
    repr_calls = 0
    bool_calls = 0
    int_calls = 0
    float_calls = 0
    iter_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("str hook called")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("repr hook called")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("bool hook called")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("int hook called")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("float hook called")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("iter hook called")


class HostileDict(dict):
    items_calls = 0
    iter_calls = 0
    keys_calls = 0
    values_calls = 0

    def items(self):
        type(self).items_calls += 1
        raise RuntimeError("items hook called")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("iter hook called")

    def keys(self):
        type(self).keys_calls += 1
        raise RuntimeError("keys hook called")

    def values(self):
        type(self).values_calls += 1
        raise RuntimeError("values hook called")


def _reset() -> None:
    HostileValue.str_calls = 0
    HostileValue.repr_calls = 0
    HostileValue.bool_calls = 0
    HostileValue.int_calls = 0
    HostileValue.float_calls = 0
    HostileValue.iter_calls = 0
    HostileDict.items_calls = 0
    HostileDict.iter_calls = 0
    HostileDict.keys_calls = 0
    HostileDict.values_calls = 0


def _contains_object_identity(root, target_id: int, *, max_nodes: int = 4096) -> bool:
    seen: set[int] = set()
    stack = [root]
    while stack and len(seen) < max_nodes:
        current = stack.pop()
        current_id = id(current)
        if current_id == target_id:
            return True
        if current_id in seen:
            continue
        seen.add(current_id)
        try:
            refs = gc.get_referents(current)
        except Exception:  # pragma: no cover - gc failure would be environmental
            refs = ()
        stack.extend(refs)
    return False


def test_stage1563_scheduler_snapshot_mapping_copies_nested_mutable_sources() -> None:
    source = {"outer": {"items": ["a", "b"]}}

    snapshot = immutable_snapshot_mapping(source, field_name="phase2_snapshot")
    source["outer"]["items"].append("late")

    exported = materialize_scheduler_mapping(snapshot)
    assert isinstance(snapshot, FrozenSchedulerMapping)
    assert exported == {"outer": {"items": ["a", "b"]}}


def test_stage1563_scheduler_snapshot_rejects_unsupported_value_without_retaining_it() -> None:
    _reset()
    hostile = HostileValue()

    snapshot = immutable_snapshot_mapping({"bad": hostile}, field_name="phase2_snapshot")
    exported = materialize_scheduler_mapping(snapshot)

    assert exported["bad"]["unsupported_scheduler_value"] is True
    assert exported["bad"]["error_category"] == "scheduler_json_materialization_unsupported"
    assert not _contains_object_identity(snapshot, id(hostile))
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.iter_calls == 0


def test_stage1563_mappingproxy_backed_by_hostile_dict_is_rejected_without_hooks() -> None:
    _reset()
    hostile_proxy = MappingProxyType(HostileDict({"safe": "value"}))

    exported = materialize_scheduler_mapping(hostile_proxy)

    assert exported["unsupported_scheduler_value"] is True
    assert exact_mapping_items(hostile_proxy) is None
    assert HostileDict.items_calls == 0
    assert HostileDict.iter_calls == 0
    assert HostileDict.keys_calls == 0
    assert HostileDict.values_calls == 0


def test_stage1563_scheduler_evidence_context_snapshot_does_not_retain_hostile_value() -> None:
    _reset()
    hostile = HostileValue()

    record = SchedulerEvidenceRecord(
        stage="phase2",
        state="failed",
        error_category="hostile_context",
        context={"bad": hostile},
    )
    exported = record.as_dict()

    assert exported["context"]["bad"]["unsupported_scheduler_value"] is True
    assert not _contains_object_identity(record.context, id(hostile))
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0


def test_stage1563_replay_snapshot_records_do_not_retain_hostile_value() -> None:
    _reset()
    hostile = HostileValue()

    snapshot = ReplaySnapshot(replay_id="phase2", records=({"bad": hostile},))
    exported = snapshot.as_dict()

    assert exported["records"][0]["bad"]["unsupported_scheduler_value"] is True
    assert not _contains_object_identity(snapshot.records, id(hostile))
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
