import inspect

from Virus_Scan.scheduler.orchestration import process_queue_child_mode
from Virus_Scan.scheduler.workers import child_result_publication as child
from Virus_Scan.scheduler.workers import process_queue_child_failure as child_failure
from Virus_Scan.scheduler.queue import issue_reporting as queue_support
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.contracts.result_record import make_worker_error_result as _contract_worker_error_result


def test_stage114_worker_error_result_is_degraded_and_non_learnable(tmp_path):
    res, info = child.worker_error_result(str(tmp_path / 'bad.bin'), RuntimeError('boom'), stage='unit', job={'attempt': 2}, make_error_result=_contract_worker_error_result, exception_info_builder=child.build_safe_exception_info, report=queue_support._stage113_record_process_queue_suppressed, recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS)
    assert res['queue_failure'] is True
    assert res['failure_info'] == info
    integrity = res['scan_integrity']
    assert integrity['queue_failure'] is True
    assert integrity['had_degraded_stage'] is True
    assert integrity['allow_learning'] is False
    tags = set(res.get('tags') or [])
    assert {'scanner_failure', 'scanner_degraded', 'scan_incomplete'} <= tags


def test_stage114_persist_child_result_records_rejection(tmp_path):
    calls = []
    report = lambda where, exc: calls.append((f'process_queue.{where}', type(exc).__name__, str(exc)))
    assert child.persist_child_result(
        child.ChildResultPersistRequest(
            queue_dir=tmp_path,
            claim_path=tmp_path / 'claim.json',
            file_path='x.bin',
            result={'tags': []},
            context='unit',
            write_result=lambda *a, **k: False,
            report=report,
            recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        )
    ) is False
    assert calls and calls[0][0] == 'process_queue.unit.result_persist_rejected'


def test_stage114_persist_child_result_records_exception(tmp_path):
    calls = []
    def boom(*a, **k):
        raise OSError('disk full')
    report = lambda where, exc: calls.append((f'process_queue.{where}', type(exc).__name__, str(exc)))
    assert child.persist_child_result(
        child.ChildResultPersistRequest(
            queue_dir=tmp_path,
            claim_path=tmp_path / 'claim.json',
            file_path='x.bin',
            result={'tags': []},
            context='unit',
            write_result=boom,
            report=report,
            recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        )
    ) is False
    assert calls and calls[0][0] == 'process_queue.unit.result_persist_exception'
    assert calls[0][1] == 'OSError'


def test_stage114_worker_output_update_records_aggregate_failure(tmp_path):
    calls = []
    report = lambda where, exc: calls.append((f'process_queue.{where}', type(exc).__name__, str(exc)))
    blocked_parent = tmp_path / "blocked-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")
    assert child.update_worker_output(
        child.WorkerOutputUpdateRequest(
            worker_output_path=blocked_parent / 'worker.json',
            file_path='x.bin',
            result={'tags': []},
            child_results={'x.bin': {'tags': []}},
            context='unit',
            report=report,
        )
    ) is False
    assert calls and calls[0][0] == 'process_queue.unit.aggregate_write_rejected'


def test_stage114_raw_queue_child_path_uses_explicit_stage114_contracts():
    src = inspect.getsource(process_queue_child_mode.run_process_queue_child_mode)
    assert 'process_queue_child_job' in src
    assert '_contract_worker_error_result' not in src
    assert 'finalize_worker_output' in src
    assert '_write_worker_output_fast' not in src
    child_src = inspect.getsource(child.update_worker_output)
    child_module_src = inspect.getsource(child)
    request_src = inspect.getsource(child.WorkerOutputUpdateRequest)
    failure_src = inspect.getsource(child_failure.build_child_failure_result)
    assert '_write_worker_output_fast' not in request_src
    assert 'write_worker_output' not in request_src
    assert '_publish_worker_output' in child_src
    assert child_module_src.count('write_worker_output_payload(') == 1
    assert 'make_scheduler_worker_error_result' in failure_src
    assert 'if "_write_queue_file_result" in globals() else True' not in src
    assert '_safe_exception_info(e, stage="queue_child_outer", worker_pid=os.getpid()' not in src
