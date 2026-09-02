from pathlib import Path

from Virus_Scan.scheduler.ownership import scheduler_identity
from Virus_Scan.scheduler.queue import identity as queue_identity
from Virus_Scan.scheduler.queue import identity_lock as process_queue_identity_lock


def test_scheduler_identity_owns_only_process_spawn_identity():
    assert scheduler_identity.__all__ == ("SchedulerProcessIdentity", "build_scheduler_process_identity")
    source = Path(scheduler_identity.__file__).read_text(encoding="utf-8")
    forbidden = (
        "queue_job_identity",
        "queue_is_job_json_name",
        "acquire_identity_lock",
        "release_identity_lock",
        "enqueue_guard",
        "identity_locks",
        "_queue_job_dirs",
    )
    for token in forbidden:
        assert token not in source


def test_queue_identity_owns_deterministic_queue_identity_only():
    assert queue_identity.queue_is_job_json_name("job.json") is True
    assert queue_identity.queue_is_job_json_name("job.json.tmp") is False
    assert queue_identity.queue_job_identity({"queue_file_id": "abc"}) == "abc"
    source = Path(queue_identity.__file__).read_text(encoding="utf-8")
    assert "def acquire_identity_lock" not in source
    assert "def release_identity_lock" not in source
    assert "identity_locks" not in source


def test_queue_identity_lock_owner_owns_lock_filesystem_transitions():
    source = Path(process_queue_identity_lock.__file__).read_text(encoding="utf-8")
    assert "def acquire_identity_lock_decision" in source
    assert "def release_identity_lock_decision" in source
    assert "def acquire_identity_lock(" not in source
    assert "def release_identity_lock(" not in source
    assert "from Virus_Scan.scheduler.ownership.scheduler_identity import" not in source


def test_process_queue_callers_do_not_import_queue_identity_from_scheduler_identity():
    for rel in (
        "Virus_Scan/scheduler/queue/claim.py",
        "Virus_Scan/scheduler/queue/publish.py",
        "Virus_Scan/scheduler/queue/process_queue_finalization.py",
        "Virus_Scan/scheduler/queue/orphan_recovery.py",
    ):
        source = Path(rel).read_text(encoding="utf-8")
        assert "from Virus_Scan.scheduler.ownership.scheduler_identity import" not in source
