from pathlib import Path
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
import inspect

from Virus_Scan.scheduler.orchestration.scheduler_runner import run_scheduler_pipeline
from Virus_Scan.scheduler.execution.process_queue_runner import run_process_queue
from Virus_Scan.scheduler.orchestration.inmemory_parent_loop import _run_longlived_process_queue
from Virus_Scan.scheduler.evidence.scheduler_json_writer import write_process_queue_json_durable
from Virus_Scan.scheduler.queue.authority import _ensure_process_queue_dirs
from Virus_Scan.scheduler.queue.orphan_recovery import _reclaim_stale_process_queue_jobs
from Virus_Scan.scheduler.queue.publish import _write_process_queue_jobs_slice
from Virus_Scan.scheduler.queue.claim import claim_process_queue_job_matching


def test_stage129_process_queue_legacy_facade_removed():
    assert not Path('Virus_Scan/scheduler/process_queue.py').exists()


def test_stage129_canonical_process_queue_entry_signature_preserved():
    sig = inspect.signature(run_process_queue)
    assert 'per_file_timeout_sec' in sig.parameters
    assert run_process_queue('/tmp', [], 1, scan_session_snapshot=scan_session_snapshot_fixture()) == {}
    assert callable(run_scheduler_pipeline)


def test_stage129_process_queue_helpers_are_owned_by_canonical_modules():
    required = [
        _ensure_process_queue_dirs,
        _reclaim_stale_process_queue_jobs,
        _write_process_queue_jobs_slice,
        claim_process_queue_job_matching,
        write_process_queue_json_durable,
        run_process_queue,
        _run_longlived_process_queue,
    ]
    for fn in required:
        assert callable(fn)
        assert 'scheduler.process_queue' not in fn.__module__


def test_stage129_durable_writer_rejects_semantically_incomplete_failure(tmp_path):
    assert write_process_queue_json_durable(
        tmp_path / 'bad.tmp',
        tmp_path / 'bad.json',
        {'queue_failure': True},
        log_context='stage129_semantic_reject',
    ) is False
    assert not (tmp_path / 'bad.json').exists()
