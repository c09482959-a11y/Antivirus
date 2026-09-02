from pathlib import Path

from Virus_Scan.scheduler.queue import raw_queue_accumulator as acc
from Virus_Scan.scheduler.queue import raw_accumulator_lock as lock_owner
from Virus_Scan.scheduler.queue.raw_accumulator_store import RawAccumulatorStore, GlobalRawAccumLock


def test_stage190_raw_accumulator_export_is_raw_queue_owned_dependency_binding():
    assert issubclass(RawAccumulatorStore, acc.RawAccumulatorStore)
    assert issubclass(GlobalRawAccumLock, lock_owner.GlobalRawAccumLock)
    store = RawAccumulatorStore(Path("."), "fid-stage190-owner")
    assert isinstance(store.deps, acc.RawAccumulatorDependencies)


def test_stage190_accumulator_preserves_reconciliation_semantics(tmp_path):
    store = RawAccumulatorStore(tmp_path, "fid-stage190")
    store.init("sample.bin", expected=1, initial_tags=["raw"], effective_stage="raw", ext_stage="bin")
    data = store.append({"tags": ["one"], "yara_hits": ["rule_a"], "ordered_events": ["e1"]})
    assert data["completed"] == 1
    assert RawAccumulatorStore.is_complete(data)

    repaired = RawAccumulatorStore.normalize_counts({"expected": 1, "completed": 1, "failed": 2, "tags": [], "errors": []})
    assert repaired["expected"] == 2
    assert repaired["completed"] == 2
    assert repaired["degraded"] is True
    assert "raw_accumulator_count_reconciled" in repaired["tags"]
