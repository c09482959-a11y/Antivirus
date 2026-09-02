from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_quarantine import (
    quarantine_destination,
    quarantine_sidecar_payload,
    remove_claim_sidecar_for_terminal_move,
)


def test_quarantine_destination_is_state_prefixed_and_collision_safe(tmp_path):
    pending = tmp_path / "pending"
    qdir = tmp_path / "quarantine"
    pending.mkdir()
    qdir.mkdir()
    job = pending / "job.json"
    job.write_text("{}", encoding="utf-8")
    first, state = quarantine_destination(job, quarantine_root=qdir)
    assert first.name == "pending__job.json"
    assert state == "pending"
    first.write_text("{}", encoding="utf-8")
    second, _ = quarantine_destination(job, quarantine_root=qdir)
    assert second.name == "pending__job__dup001.json"


def test_quarantine_sidecar_payload_is_deterministic_for_supplied_time(tmp_path):
    dest = tmp_path / "quarantine" / "active__job.json"
    payload = quarantine_sidecar_payload(
        reason="duplicate", identity="sha256:abc", source_state="active", destination=dest, now=10.0
    )
    assert payload["quarantined"] is True
    assert payload["quarantine_reason"] == "duplicate"
    assert payload["queue_identity"] == "sha256:abc"
    assert payload["quarantine_source_state"] == "active"
    assert payload["quarantine_job"] == "active__job.json"
    assert payload["quarantine_time"] == 10.0


def test_terminal_sidecar_cleanup_reports_failures(tmp_path):
    claim = tmp_path / "active" / "job.json"
    seen = []

    def remove(_claim):
        raise RuntimeError("locked")

    def report(stage, exc, **kwargs):
        seen.append((stage, type(exc).__name__, kwargs))

    assert remove_claim_sidecar_for_terminal_move(
        claim, remove_claim_meta=remove, report=report, marker="cleanup_failed"
    ) is False
    assert seen and seen[0][0] == "cleanup_failed"
