import inspect

import Virus_Scan.scheduler.workers.inmemory_worker_process as worker_process
import Virus_Scan.scheduler.workers.process_queue_child_failure as child_failure


def test_stage733_worker_process_uses_scheduler_worker_result_contract():
    src = inspect.getsource(worker_process)
    assert "Virus_Scan.contracts.result_record" not in src
    assert "make_scheduler_worker_error_result" in src


def test_stage733_child_failure_uses_scheduler_worker_result_contract():
    src = inspect.getsource(child_failure)
    assert "Virus_Scan.contracts.result_record" not in src
    assert "make_scheduler_worker_error_result" in src
