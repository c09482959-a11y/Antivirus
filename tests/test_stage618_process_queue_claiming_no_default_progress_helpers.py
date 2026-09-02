from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path



def test_process_queue_claiming_does_not_own_raw_progress_defaults():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/claim.py"))
    assert "def _queue_raw_stage_progress_recent" not in source
    assert "def _queue_file_has_recent_raw_owner_progress" not in source
    assert "return False\n\ndef _queue_file_has_recent_raw_owner_progress" not in source


def test_process_queue_claiming_imports_queue_dir_authority_from_canonical_owner_once():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/claim.py"))
    assert source.count("_ensure_process_queue_dirs") == 2  # canonical grouped import + local claim setup call
    assert "from Virus_Scan.scheduler.queue.authority import _ensure_process_queue_dirs" not in source
    assert "'_ensure_process_queue_dirs'" not in source
