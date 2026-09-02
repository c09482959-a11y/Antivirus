import inspect

import Virus_Scan.scheduler.workers.inmemory_file_scan as inmemory_file_scan


def test_stage733_inmemory_file_scan_uses_scheduler_worker_result_contract():
    src = inspect.getsource(inmemory_file_scan)
    assert "Virus_Scan.contracts.result_record" not in src
    assert "make_scheduler_worker_error_result" in src
