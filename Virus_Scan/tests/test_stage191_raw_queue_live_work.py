from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_live_work import RawQueueLiveWorkDependencies, raw_queue_has_live_work
from Virus_Scan.scheduler.queue.raw_accumulator_store import RawAccumulatorStore


def _dirs(root):
    dirs = tuple(root / name for name in ("pending", "active", "done", "failed", "accum", "locks"))
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def test_stage191_live_work_detects_pending_jobs(tmp_path):
    pending, *_ = _dirs(tmp_path)
    (pending / "job.json").write_text("{}")
    deps = RawQueueLiveWorkDependencies(
        global_raw_dirs=lambda q: _dirs(q),
        read_json=lambda path, default=None: default,
        raw_accumulator_store=RawAccumulatorStore,
        ordered_unique_tags=lambda tags: list(dict.fromkeys(tags)),
        write_json_durable=lambda *a, **k: True,
        record_suppressed=lambda where, exc: None,
    )
    assert raw_queue_has_live_work(tmp_path, deps) is True


def test_stage191_live_work_closes_stale_accumulator(tmp_path):
    *_unused, accum, _locks = _dirs(tmp_path)
    ap = accum / "file.json"
    ap.write_text("{}")
    writes = []

    def read_json(path, default=None):
        return {"expected": 2, "completed": 1, "failed": 0, "tags": []}

    def write_json(tmp, final, payload, **kwargs):
        writes.append((tmp, final, payload, kwargs))
        return True

    deps = RawQueueLiveWorkDependencies(
        global_raw_dirs=lambda q: _dirs(q),
        read_json=read_json,
        raw_accumulator_store=RawAccumulatorStore,
        ordered_unique_tags=lambda tags: list(dict.fromkeys(tags)),
        write_json_durable=write_json,
        record_suppressed=lambda where, exc: None,
        current_time=lambda: 1000.0,
        path_mtime=lambda path: 0.0,
        environment_value=lambda name, default=None: "1" if name == "UMIGE_RAW_ACCUMULATOR_STALL_SEC" else default,
    )
    assert raw_queue_has_live_work(tmp_path, deps) is False
    assert writes
    payload = writes[0][2]
    assert payload["closed"] is True
    assert payload["degraded"] is True
    assert "raw_accumulator_stalled" in payload["tags"]
