from Virus_Scan.tests.support.static_inventory import python_files_under, read_python_file

from pathlib import Path



def test_stage714_reconciliation_folder_is_no_longer_queue_or_retry_owner():
    recon = Path("Virus_Scan/scheduler/reconciliation")
    remaining = sorted(p.name for p in recon.glob("*.py") if p.name != "__init__.py")
    assert remaining == []


def test_stage714_queue_owns_recovery_retry_and_raw_queue_modules():
    queue = Path("Virus_Scan/scheduler/queue")
    expected = {
        "recovery_contract.py",
        "inmemory_retry_recovery.py",
        "inmemory_recovery_coordinator.py",
        "inmemory_lifecycle.py",
        "inmemory_lifecycle_journal.py",
        "raw_queue_cleanup.py",
        "raw_queue_counts.py",
        "raw_queue_duplicates.py",
        "raw_queue_recovery.py",
        "state_io.py",
        "terminal_accounting.py",
        "process_queue_finalization.py",
        "process_queue_stale_recovery.py",
    }
    missing = sorted(name for name in expected if not (queue / name).exists())
    assert missing == []
    assert not (queue / "raw_queue_finalization.py").exists()


def test_stage714_worker_shutdown_and_exit_are_worker_owned():
    workers = Path("Virus_Scan/scheduler/workers")
    expected = {
        "ipc_lifecycle.py",
        "inmemory_shutdown.py",
        "inmemory_worker_death.py",
        "process_queue_worker_exit.py",
    }
    missing = sorted(name for name in expected if not (workers / name).exists())
    assert missing == []


def test_stage714_no_code_imports_scheduler_reconciliation_modules():
    roots = ("Virus_Scan/scheduler", "Virus_Scan/tests", "tests")
    offenders = []
    needle = "Virus_Scan.scheduler." + "reconciliation"
    for root in roots:
        for path in python_files_under(root):
            if needle in read_python_file(path):
                offenders.append(str(path))
    assert offenders == []


def test_stage714_worker_authority_split_deleted_old_surface():
    assert not Path("Virus_Scan/scheduler/ownership/worker_authority.py").exists()
    for name in ("process_liveness.py", "process_termination.py", "process_snapshots.py", "retire_tokens.py", "lifecycle_boundary.py"):
        assert (Path("Virus_Scan/scheduler/workers") / name).exists()
