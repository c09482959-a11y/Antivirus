from pathlib import Path

from Virus_Scan.scheduler.queue import orphan_recovery, publish, reclaim_publication
from Virus_Scan.scheduler.queue.orphan_recovery_actions import requeue_reclaimed_active_job
from Virus_Scan.scheduler.queue.orphan_recovery_claim_state import load_active_claim_state
from Virus_Scan.scheduler.queue.orphan_recovery_policy import load_queue_reclaim_policy


def test_stage709_reclaim_recovery_is_split_into_queue_owned_modules():
    source = Path(orphan_recovery.__file__).read_text(encoding="utf-8")
    assert "load_active_claim_state" in source
    assert "load_queue_reclaim_policy" in source
    assert "requeue_reclaimed_active_job" in source
    assert len(source.splitlines()) < 250
    assert reclaim_publication._publish_reclaimed_pending_job is orphan_recovery._publish_reclaimed_pending_job
    assert callable(load_active_claim_state)
    assert callable(load_queue_reclaim_policy)
    assert callable(requeue_reclaimed_active_job)


def test_stage709_dead_reconciliation_orphan_cleanup_removed():
    assert not Path("Virus_Scan/scheduler/reconciliation/orphan_cleanup.py").exists()
    assert not Path("Virus_Scan/scheduler/ownership/process_queue_publish.py").exists()
    assert Path(publish.__file__).as_posix().endswith("scheduler/queue/publish.py")
