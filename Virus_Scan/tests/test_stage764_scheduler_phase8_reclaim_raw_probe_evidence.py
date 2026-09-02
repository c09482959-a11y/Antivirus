from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.orphan_recovery_timeout import classify_reclaim_timeout


def test_stage764_reclaim_raw_progress_probe_failure_is_timeout_evidence(tmp_path: Path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"data")

    def raw_stage_progress_recent(_queue_dir, quiet_sec=None):
        raise RuntimeError("raw progress probe unavailable")

    decision = classify_reclaim_timeout(
        job={"file": str(target), "job_type": "file", "queue_info": {}},
        queue_dir=tmp_path,
        claim_age=10.0,
        progress_age=10.0,
        hb_age=10.0,
        heartbeat_fresh=True,
        pid_alive=True,
        stale=300.0,
        file_timeout=300.0,
        progress_stall=300.0,
        timeout_expired=False,
        checkpoint_stalled=False,
        raw_stage_progress_recent=raw_stage_progress_recent,
    )

    assert decision.continue_claim is True
    assert decision.timeout_evidence["raw_global_progress_probe_failed"] is True
    evidence = decision.timeout_evidence["raw_global_progress_probe_evidence"]
    assert evidence["stage"] == "process_queue_reclaim_timeout_raw_progress_probe"
    assert evidence["timeout_failure"] is True
    assert evidence["queue_recovery_failure"] is True
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
