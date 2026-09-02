import json, os, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor


from Virus_Scan.scheduler.runtime.queue_json import _queue_write_json_replace
from Virus_Scan.scheduler.queue.orphan_recovery import _queue_reset_retry_runtime_metadata
from Virus_Scan.scheduler.queue.authority import _ensure_process_queue_dirs
from Virus_Scan.scheduler.queue.process_queue_finalization import _finish_process_queue_job
from Virus_Scan.runtime.causal_event_stream import EventBus
from Virus_Scan.scheduler.queue.quarantine import _queue_quarantine_job

def test_stage79_json_replace_cleans_orphan_temps(tmp_path):
    target = tmp_path / "state.json"
    old = tmp_path / "state.json.tmp.1.2.3"
    old.write_text('{"stale": true}', encoding='utf-8')
    os.utime(old, (time.time() - 3600, time.time() - 3600))
    fresh = tmp_path / "state.json.tmp.1.2.fresh"
    fresh.write_text('{"fresh": true}', encoding='utf-8')
    _queue_write_json_replace(target, {"job_type": "unit", "value": 1}, verify=True)
    assert not old.exists()
    assert fresh.exists()
    loaded = json.loads(target.read_text(encoding='utf-8'))
    assert loaded["schema_version"] == 1


def test_stage79_concurrent_json_replace_has_no_corrupt_or_orphan_temps(tmp_path):
    target = tmp_path / "result.json"
    def writer(i):
        return _queue_write_json_replace(target, {"job_type":"unit", "i":i}, verify=True)
    with ThreadPoolExecutor(max_workers=32) as ex:
        results = list(ex.map(writer, range(256)))
    assert all(results)
    data = json.loads(target.read_text(encoding='utf-8'))
    assert isinstance(data.get('i'), int)
    assert data.get('schema_version') == 1
    assert not [p for p in tmp_path.iterdir() if p.name.startswith('result.json.tmp.') and p.stat().st_mtime < time.time() - 0.01]


def test_stage79_retry_metadata_reset_blocks_stale_resurrection():
    job = {"attempt": 1, "claimed_by": "worker-a", "heartbeat_time": 1.0, "active_claim": "active/x", "queue_info": {"claimed_time": 1.0, "heartbeat_time": 2.0, "worker_pid": 123, "progress_marker": "old"}}
    out = _queue_reset_retry_runtime_metadata(job, now=100.0, reason="unit")
    assert "claimed_by" not in out and "active_claim" not in out and "heartbeat_time" not in out
    qi = out["queue_info"]
    assert "claimed_time" not in qi and "worker_pid" not in qi and "progress_marker" not in qi
    assert qi["retry_pending_time"] == 100.0
    assert qi["retry_generation"] == 1


def test_stage79_finish_is_idempotent_under_duplicate_recovery(tmp_path):
    q = tmp_path / "queue"
    _ensure_process_queue_dirs(q)
    claim = q / "active" / "worker_1_job.json"
    claim.write_text(json.dumps({"job_type":"file", "file":"x"}), encoding='utf-8')
    _finish_process_queue_job(q, claim, ok=True, job={"job_type":"file", "file":"x"})
    _finish_process_queue_job(q, claim, ok=True, job={"job_type":"file", "file":"x"})
    assert (q / "done" / claim.name).exists()
    assert not list((q / "failed").glob("*.json"))


def test_stage79_event_restore_advances_sequence_and_replay_is_timestamp_independent():
    b = EventBus()
    a = b.emit('runtime','unit', {'x':1})
    b.emit('runtime','unit2', {'x':2}, parent_seq=a.seq)
    cp = b.deterministic_checkpoint()
    restored = EventBus()
    restored.restore_checkpoint(cp)
    ev = restored.emit('runtime','after', {'x':3})
    assert ev.seq == 3
    assert restored.invariant_snapshot()['ok'] is True
    d1 = restored.replay_digest()
    # Timestamp changes must not alter canonical replay digest.
    cp2 = restored.deterministic_checkpoint()
    for item in cp2['events']:
        item['timestamp'] = time.time() + 9999
    restored2 = EventBus(); restored2.restore_checkpoint(cp2)
    assert restored2.replay_digest() == d1


def test_stage79_quarantine_uses_unique_immutable_artifacts(tmp_path):
    q = tmp_path / "queue"; pending = q / "pending"; pending.mkdir(parents=True)
    job1 = pending / "job.json"; job1.write_text(json.dumps({"job_type":"file", "file":"a"}), encoding='utf-8')
    assert _queue_quarantine_job(job1, reason="unit")
    # Same basename later must not overwrite first artifact or its sidecar.
    job2 = pending / "job.json"; job2.write_text(json.dumps({"job_type":"file", "file":"b"}), encoding='utf-8')
    assert _queue_quarantine_job(job2, reason="unit2")
    qs = sorted((q / "quarantine").glob("*.json"))
    assert len(qs) == 2
    assert len({p.name for p in qs}) == 2
    assert all((p.with_name(p.name + '.qmeta')).exists() or list(p.parent.glob(p.name + '.qmeta.*')) for p in qs)
