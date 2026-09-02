from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.scheduler.queue.orphan_recovery import OrphanReclaimRequest, _reclaim_stale_process_queue_jobs
from Virus_Scan.scheduler.queue.orphan_recovery_claim_state import load_active_claim_state


def test_stage2188_claim_payload_deferral_is_replayable(tmp_path: Path) -> None:
    active = tmp_path / "active.json"
    active.write_text("[1]", encoding="utf-8")
    evidence: list[dict[str, object]] = []

    state = load_active_claim_state(
        active,
        now=active.stat().st_mtime + 30.0,
        stale=60.0,
        file_timeout=90.0,
        progress_stall=60.0,
        worker_liveness_checker=lambda *_args, **_kwargs: {"alive": False},
        deferred_recovery_evidence=evidence,
    )

    assert state is None
    assert len(evidence) == 1
    assert evidence[0]["error_category"] == "orphan_claim_payload_deferred"
    assert evidence[0]["final_json_must_record"] is True
    assert evidence[0]["checkpoint_must_record"] is True
    assert evidence[0]["replay_must_record"] is True


def test_stage2188_claim_metadata_deferral_reaches_recovery_result(tmp_path: Path) -> None:
    queue = tmp_path / "queue"
    active = queue / "active"
    active.mkdir(parents=True)
    (queue / "pending").mkdir()
    (queue / "done").mkdir()
    (queue / "failed").mkdir()
    claim = active / "sample.json"
    claim.write_text(json.dumps({"file": "sample.bin", "queue_info": {}}), encoding="utf-8")

    result = _reclaim_stale_process_queue_jobs(
        OrphanReclaimRequest(
            queue_dir=queue,
            stale_sec=60.0,
            max_retries=1,
            progress_stall_sec=60.0,
            per_file_timeout_sec=90.0,
            raw_stage_progress_recent=lambda *_args, **_kwargs: False,
            file_has_recent_raw_owner_progress=lambda *_args, **_kwargs: False,
            worker_liveness_checker=lambda *_args, **_kwargs: {"alive": False},
            worker_terminator=lambda *_args, **_kwargs: False,
        )
    )

    assert result["requeued"] == 0
    assert result["failed"] == 0
    evidence = result["timeout_retry_evidence"]
    assert evidence[0]["error_category"] == "orphan_claim_metadata_deferred"
    assert evidence[0]["final_json_must_record"] is True
    assert evidence[0]["checkpoint_must_record"] is True
    assert evidence[0]["replay_must_record"] is True
