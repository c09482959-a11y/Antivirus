from pathlib import Path


from Virus_Scan.scheduler.execution.scan_job_executor import (
    RawQueueJobExecutionDependencies,
    process_one_raw_stage_job,
)


def test_scan_job_executor_module_imports():

    assert RawQueueJobExecutionDependencies is not None
    assert callable(process_one_raw_stage_job)


def test_raw_queue_process_one_job_surface_removed_after_canonical_execution_collapse():
    assert not Path(__file__).resolve().parents[1].joinpath('scheduler/raw_queue.py').exists()
