from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path



def test_stage734_worker_progress_modules_are_worker_owned():
    assert not Path("Virus_Scan/scheduler/execution/thread_progress.py").exists()
    assert not Path("Virus_Scan/scheduler/execution/inmemory_scan_progress.py").exists()
    assert Path("Virus_Scan/scheduler/workers/thread_progress.py").exists()
    assert Path("Virus_Scan/scheduler/workers/inmemory_scan_progress.py").exists()


def test_stage734_inmemory_file_scan_uses_worker_progress_boundaries():
    src = read_python_file(Path("Virus_Scan/scheduler/workers/inmemory_file_scan.py"))
    assert "Virus_Scan.scheduler.workers.thread_progress" in src
    assert "Virus_Scan.scheduler.workers.inmemory_scan_progress" in src
    assert "Virus_Scan.scheduler.execution.thread_progress" not in src
    assert "Virus_Scan.scheduler.execution.inmemory_scan_progress" not in src
