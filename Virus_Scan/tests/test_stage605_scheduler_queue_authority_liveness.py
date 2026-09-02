from pathlib import Path

from Virus_Scan.scheduler.queue import authority as queue_authority
from Virus_Scan.scheduler.queue import claim as process_queue_claiming
from Virus_Scan.scheduler.queue import orphan_recovery as process_queue_recovery


def test_queue_claim_mtime_age_is_queue_authority_owned(tmp_path):
    seen = []
    missing = tmp_path / "missing-active.json"

    assert queue_authority.queue_path_mtime_age(
        missing,
        now=123.0,
        record_suppressed=lambda where, exc, **kw: seen.append((where, type(exc).__name__, kw)),
    ) is None
    assert seen[0][0] == "process_queue_active_claim_mtime_unavailable"
    assert seen[0][2]["extra"]["path"] == str(missing)


def test_claiming_recovery_use_queue_authority_clock():
    assert process_queue_recovery._process_queue_queue_now is queue_authority.queue_now


def test_execution_process_queue_liveness_deleted_not_wrapped():
    assert not Path("Virus_Scan/scheduler/execution/process_queue_liveness.py").exists()
