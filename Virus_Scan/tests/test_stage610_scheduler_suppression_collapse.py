from Virus_Scan.tests.support.static_inventory import python_files_under, read_python_file

from pathlib import Path


from Virus_Scan.scheduler.execution.target_collection import collect_target_files
from Virus_Scan.scheduler.queue import dirs as process_queue_dirs
from Virus_Scan.scheduler.queue import raw_queue_cleanup, raw_queue_quarantine


def test_suppression_package_deleted_after_behavior_moves():
    root = Path(__file__).resolve().parents[1] / "scheduler"
    assert not (root / "suppression").exists()


def test_target_collection_owned_by_execution():
    assert collect_target_files.__module__ == "Virus_Scan.scheduler.execution.target_collection"


def test_process_queue_cleanup_and_quarantine_owned_by_process_queue_dirs():
    assert process_queue_dirs.cleanup_diagnostic_tmp_files.__module__ == "Virus_Scan.scheduler.queue.dirs"
    assert process_queue_dirs.process_queue_quarantine_job.__module__ == "Virus_Scan.scheduler.queue.dirs"
    assert raw_queue_cleanup.cleanup_orphan_claim_meta.__module__ == "Virus_Scan.scheduler.queue.raw_queue_cleanup"
    assert raw_queue_quarantine.quarantine_job_decision.__module__ == "Virus_Scan.scheduler.queue.raw_queue_quarantine"


def test_no_imports_reference_obsolete_suppression_package():
    root = Path(__file__).resolve().parents[1]
    offenders = []
    for path in python_files_under("Virus_Scan"):
        text = read_python_file(path)
        if "scheduler" + ".suppression" in text:
            offenders.append(path.relative_to(root).as_posix())
    assert offenders == []
