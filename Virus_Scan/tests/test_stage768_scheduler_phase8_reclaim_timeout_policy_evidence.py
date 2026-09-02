from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.orphan_recovery_timeout import classify_reclaim_timeout


def test_stage768_reclaim_timeout_malformed_policy_values_emit_evidence(tmp_path: Path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"data")

    decision = classify_reclaim_timeout(
        job={"file": str(target), "job_type": "file", "recursion_depth": object(), "queue_info": {}},
        queue_dir=tmp_path,
        claim_age="bad-claim-age",
        progress_age="bad-progress-age",
        hb_age="bad-hb-age",
        heartbeat_fresh=True,
        pid_alive=True,
        stale="bad-stale-budget",
        file_timeout="bad-file-timeout",
        progress_stall="bad-progress-stall",
        timeout_expired=False,
        checkpoint_stalled=False,
        raw_stage_progress_recent=lambda _queue_dir, quiet_sec=None: False,
    )

    evidence = decision.timeout_evidence
    assert evidence["reclaim_timeout_policy_failed"] is True
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
    reasons = {item["reason"] for item in evidence["reclaim_timeout_policy_evidence"]}
    assert "file_timeout_malformed" in reasons
    assert "progress_stall_malformed" in reasons
    assert "stale_malformed" in reasons
    assert "claim_age_malformed" in reasons
    assert "progress_age_malformed" in reasons
    assert "hb_age_malformed" in reasons
    assert "recursion_depth_malformed" in reasons
    for item in evidence["reclaim_timeout_policy_evidence"]:
        assert item["timeout_failure"] is True
        assert item["queue_recovery_failure"] is True
        assert item["final_json_must_record"] is True
        assert item["checkpoint_must_record"] is True
        assert item["replay_must_reproduce"] is True


def test_stage768_reclaim_timeout_non_mapping_job_record_emits_evidence(tmp_path: Path):
    decision = classify_reclaim_timeout(
        job=object(),
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
        raw_stage_progress_recent=lambda _queue_dir, quiet_sec=None: False,
    )

    evidence = decision.timeout_evidence
    reasons = {item["reason"] for item in evidence["reclaim_timeout_policy_evidence"]}
    assert "job_record_malformed" in reasons
    assert evidence["final_json_must_record"] is True
