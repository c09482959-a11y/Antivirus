from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path



def test_process_queue_claiming_no_queue_time_aliases():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/claim.py"))
    assert "queue_now as _process_queue_queue_now" not in source
    assert "queue_path_mtime_age as _process_queue_path_mtime_age" not in source
    assert "_process_queue_queue_now" not in source
    assert "_process_queue_path_mtime_age" not in source


def test_recovery_owns_queue_time_use_directly():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/orphan_recovery.py"))
    claim_state_source = read_python_file(Path("Virus_Scan/scheduler/queue/orphan_recovery_claim_state.py"))
    assert "from Virus_Scan.scheduler.queue.authority import" in source
    assert "queue_now as _process_queue_queue_now" in source
    assert "queue_path_mtime_age as _process_queue_path_mtime_age" in claim_state_source
