from pathlib import Path

from Virus_Scan.scheduler.queue.raw_accumulator_store import RawAccumulatorStore, global_raw_dirs, write_raw_json_durable
from Virus_Scan.scheduler.queue.raw_queue_live_work import RawQueueLiveWorkDependencies, raw_queue_has_live_work
from Virus_Scan.scheduler.runtime.queue_json import read_json_file as _queue_read_json_file
from Virus_Scan.scheduler.evidence.suppressed_failures import record_raw_queue_suppressed
from Virus_Scan.utils.tagging import ordered_unique_tags


def _dirs(root: Path):
    return tuple(root / name for name in ("pending", "active", "done", "failed", "accumulators", "locks"))


def test_stage119_reconcile_expected_lowers_publish_count_without_reinit_masking(tmp_path):
    store = RawAccumulatorStore(tmp_path, "fid-stage119-reconcile")
    store.init(tmp_path / "x.bin", expected=10, initial_tags=["global_raw_queue_scan"], effective_stage="binary", ext_stage="binary", identity={})

    # Stage118 called init(expected=published) here, but init deliberately keeps a
    # larger existing expectation.  Stage119 uses an explicit reconcile contract.
    data = store.reconcile_expected(6, reason="test_publish_throttled")

    assert data["expected"] == 6
    assert data["completed"] == 0
    assert data["degraded"] is True
    assert "raw_accumulator_expected_reconciled" in set(data.get("tags") or [])
    assert any("test_publish_throttled" in e for e in data.get("errors") or [])


def test_stage119_reconcile_expected_never_drops_below_completed(tmp_path):
    store = RawAccumulatorStore(tmp_path, "fid-stage119-completed")
    store.init(tmp_path / "x.bin", expected=5, initial_tags=[], effective_stage="binary", ext_stage="binary", identity={})
    for idx in range(3):
        store.append({"collector": "identity", "seq": idx, "tags": ["identity"]})

    data = store.reconcile_expected(1, reason="bad_lower_bound")

    assert data["completed"] == 3
    assert data["expected"] == 3
    assert RawAccumulatorStore.is_complete(data) is True
    assert data["degraded"] is True


def test_stage119_normalize_counts_repairs_bool_failed_without_clean_state():
    data = RawAccumulatorStore.normalize_counts({
        "file_id": "fid-stage119-bool",
        "expected": 2,
        "completed": 0,
        "failed": True,
        "tags": [],
        "errors": [],
    })

    assert data["failed"] == 1
    assert data["completed"] == 1
    assert data["expected"] == 2
    assert data["degraded"] is True
    assert "raw_accumulator_count_reconciled" in set(data.get("tags") or [])


def test_stage119_stale_accumulator_mark_preserves_integer_failed_and_degraded_tags(tmp_path):
    pending, active, done, failed, accum, locks = _dirs(tmp_path)
    for d in (pending, active, done, failed, accum, locks):
        d.mkdir(parents=True, exist_ok=True)
    ap = accum / "fid-stage119-stale.json"
    ap.write_text('{"file_id":"fid-stage119-stale","expected":4,"completed":1,"failed":0,"tags":[]}', encoding="utf-8")
    deps = RawQueueLiveWorkDependencies(
        global_raw_dirs=global_raw_dirs,
        read_json=_queue_read_json_file,
        raw_accumulator_store=RawAccumulatorStore,
        ordered_unique_tags=ordered_unique_tags,
        write_json_durable=write_raw_json_durable,
        record_suppressed=record_raw_queue_suppressed,
        current_time=lambda: 1000.0,
        path_mtime=lambda path: 0.0,
        environment_value=lambda name, default=None: "1" if name == "UMIGE_RAW_ACCUMULATOR_STALL_SEC" else default,
    )
    assert raw_queue_has_live_work(tmp_path, deps) is False
    data = _queue_read_json_file(ap, default={})
    assert data["failed"] == 3
    assert data["completed"] == 4
    assert data["degraded"] is True
    assert {"raw_accumulator_stalled", "scanner_failure", "scanner_degraded", "scan_incomplete"} <= set(data.get("tags") or [])
