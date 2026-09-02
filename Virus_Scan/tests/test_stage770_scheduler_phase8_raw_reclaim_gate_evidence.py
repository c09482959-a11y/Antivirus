from __future__ import annotations

from Virus_Scan.scheduler.queue.orphan_recovery_gates import (
    apply_raw_owner_reclaim_gate,
    apply_raw_stage_reclaim_gate,
)


def _assert_gate_evidence(record, stage):
    assert record["stage"] == stage
    assert record["timeout_failure"] is True
    assert record["retry_failure"] is True
    assert record["queue_recovery_failure"] is True
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True


def test_stage770_raw_stage_reclaim_gate_probe_failure_records_evidence(tmp_path):
    evidence = []

    def raising_probe(*_args, **_kwargs):
        raise RuntimeError("raw stage probe failed")

    should_continue, timeout_expired, checkpoint_stalled = apply_raw_stage_reclaim_gate(
        job={"job_type": "raw_stage", "file": "raw.bin"},
        queue_dir=tmp_path,
        claim_age=1000.0,
        progress_age=1000.0,
        file_timeout=30.0,
        progress_stall=30.0,
        heartbeat_fresh=False,
        pid_alive=False,
        raw_stage_progress_recent=raising_probe,
        timeout_expired=False,
        checkpoint_stalled=False,
        evidence_records=evidence,
    )

    assert should_continue is True
    assert timeout_expired is False
    assert checkpoint_stalled is False
    assert evidence
    _assert_gate_evidence(evidence[0], "process_queue_raw_stage_reclaim_gate_probe_failed")


def test_stage770_raw_owner_reclaim_gate_probe_failure_records_evidence(tmp_path):
    evidence = []

    def raising_probe(*_args, **_kwargs):
        raise RuntimeError("raw owner probe failed")

    should_continue, timeout_expired, checkpoint_stalled = apply_raw_owner_reclaim_gate(
        job={"job_type": "file", "file": "owner.bin"},
        queue_dir=tmp_path,
        claim_age=1000.0,
        progress_age=1000.0,
        file_timeout=30.0,
        progress_stall=30.0,
        file_has_recent_raw_owner_progress=raising_probe,
        timeout_expired=False,
        checkpoint_stalled=False,
        evidence_records=evidence,
    )

    assert should_continue is True
    assert timeout_expired is False
    assert checkpoint_stalled is False
    _assert_gate_evidence(evidence[0], "process_queue_raw_owner_reclaim_gate_probe_failed")


def test_stage770_raw_owner_reclaim_gate_schema_failure_records_evidence(tmp_path):
    evidence = []

    should_continue, timeout_expired, checkpoint_stalled = apply_raw_owner_reclaim_gate(
        job={"job_type": "file", "file": "owner.bin"},
        queue_dir=tmp_path,
        claim_age=1000.0,
        progress_age=1000.0,
        file_timeout=30.0,
        progress_stall=30.0,
        file_has_recent_raw_owner_progress=lambda *_args, **_kwargs: object(),
        timeout_expired=False,
        checkpoint_stalled=False,
        evidence_records=evidence,
    )

    assert should_continue is True
    assert timeout_expired is False
    assert checkpoint_stalled is False
    _assert_gate_evidence(evidence[0], "process_queue_raw_owner_reclaim_gate_schema_failed")
