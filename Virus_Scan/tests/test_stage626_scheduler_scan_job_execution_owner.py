import inspect

from Virus_Scan.scheduler.orchestration import scheduler_runner as scheduler_pipeline
from Virus_Scan.scheduler.orchestration import scheduler_file_worker
from Virus_Scan.scheduler.workers import inmemory_file_scan_steps
from Virus_Scan.scheduler.orchestration import scheduler_pipeline_runtime
from Virus_Scan.scheduler.execution.scheduler_file_job import execute_scheduler_file_job
from Virus_Scan.scheduler.execution import scheduler_file_cache


def test_scheduler_file_execution_owned_by_scheduler_file_job():
    runner_source = inspect.getsource(scheduler_pipeline.run_scheduler_pipeline)
    worker_source = inspect.getsource(scheduler_file_worker.build_scheduler_file_worker)
    shared_source = inspect.getsource(scheduler_file_cache.execute_scheduler_file_with_cache)

    assert "build_scheduler_file_worker" in runner_source
    assert "execute_scheduler_file_job" not in runner_source
    assert "execute_scheduler_file_with_cache" in worker_source
    assert "execute_scheduler_file_job" in shared_source
    process_source = inspect.getsource(inmemory_file_scan_steps.execute_inmemory_scan_context)
    assert "execute_scheduler_file_with_cache" in process_source
    assert "complete_inmemory_analysis_result" not in process_source
    assert "scan_file_by_type(" not in runner_source
    assert "scan_file_by_type(" not in worker_source
    assert "analyze_file_full_observe_only(" not in runner_source
    assert "analyze_file_full_observe_only(" not in worker_source
    assert not hasattr(scheduler_pipeline_runtime, "build_scheduler_file_worker")
    assert execute_scheduler_file_job.__module__ == "Virus_Scan.scheduler.execution.scheduler_file_job"
    assert scheduler_file_cache.execute_scheduler_file_with_cache.__module__ == "Virus_Scan.scheduler.execution.scheduler_file_cache"
