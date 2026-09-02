from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path



def test_inmemory_raw_worker_execution_modules_are_worker_owned():
    worker_dir = Path("Virus_Scan/scheduler/workers")
    expected = {
        "inmemory_raw_scan.py",
        "inmemory_raw_failure.py",
        "inmemory_raw_finalization.py",
        "inmemory_raw_jobs.py",
        "inmemory_raw_plan.py",
    }
    assert expected <= {p.name for p in worker_dir.glob("inmemory_raw_*.py")}
    execution_dir = Path("Virus_Scan/scheduler/execution")
    assert not list(execution_dir.glob("inmemory_raw_*.py"))


def test_inmemory_worker_file_scan_uses_worker_owned_raw_scan_boundary():
    text = read_python_file(Path("Virus_Scan/scheduler/workers/inmemory_file_scan.py"))
    assert "Virus_Scan.scheduler.workers.inmemory_raw_scan import scan_file_inmemory_raw" in text
    assert "Virus_Scan.scheduler.execution.inmemory_raw_scan" not in text


def test_inmemory_raw_dependency_factory_builds_context_owned_raw_dependencies():
    text = read_python_file(Path("Virus_Scan/scheduler/context/inmemory_raw_dependency_factory.py"))
    assert "Virus_Scan.scheduler.context.inmemory_raw_dependencies" in text
    assert "Virus_Scan.scheduler.execution.inmemory_raw_dependencies" not in text
