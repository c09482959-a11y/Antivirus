from Virus_Scan.tests.support.static_inventory import python_files_under, read_python_file

from Virus_Scan.scheduler.workers.metadata import attach_worker_metadata
from Virus_Scan.scheduler.queue.raw_queue_live_work import normalize_live_accumulator_counts

from pathlib import Path



def test_scheduler_telemetry_package_removed():
    root = Path(__file__).resolve().parents[1] / "scheduler"
    assert not (root / "telemetry").exists()


def test_scheduler_imports_do_not_reference_telemetry_package():
    root = Path(__file__).resolve().parents[1]
    offenders = []
    for path in python_files_under("Virus_Scan/scheduler"):
        text = read_python_file(path)
        if "Virus_Scan.scheduler.telemetry" in text or "scheduler.telemetry" in text:
            offenders.append(path.relative_to(root).as_posix())
    assert offenders == []


def test_worker_metadata_is_evidence_owned():

    result = attach_worker_metadata({"verdict": "clean"}, scheduler_mode="process", worker_id="w1", worker_pid="123")
    assert result["scheduler_mode"] == "process"
    assert result["worker_id"] == "w1"
    assert result["worker_pid"] == 123


def test_raw_live_work_is_reconciliation_owned():

    assert normalize_live_accumulator_counts({"expected": "3", "completed": "1", "failed": "2"}) == {
        "expected": 3,
        "completed": 1,
        "failed": 2,
    }
