import Virus_Scan.scheduler.execution as execution_pkg

from pathlib import Path
import inspect

import Virus_Scan.scheduler.queue.integrity_pipeline as queue_integrity_pipeline
import Virus_Scan.scheduler.queue.results as queue_results
import Virus_Scan.scheduler.context.inmemory_raw_dependency_factory as raw_context


def test_process_queue_support_is_queue_owned_not_execution_owned():
    assert Path(queue_integrity_pipeline.__file__).parts[-3:] == ("scheduler", "queue", "integrity_pipeline.py")
    assert Path(queue_results.__file__).parts[-3:] == ("scheduler", "queue", "results.py")
    source = inspect.getsource(queue_integrity_pipeline) + inspect.getsource(queue_results)
    assert "scheduler.execution.process_queue_support" not in source
    assert hasattr(queue_integrity_pipeline, "queue_integrity_verify_and_repair")
    assert not hasattr(queue_integrity_pipeline, "_queue_integrity_verify_and_repair")
    assert hasattr(queue_results, "load_queue_file_results")
    assert not hasattr(queue_results, "_load_queue_file_results")


def test_inmemory_raw_dependency_factory_is_context_owned_not_execution_owned():
    assert Path(raw_context.__file__).parts[-3:] == ("scheduler", "context", "inmemory_raw_dependency_factory.py")
    source = inspect.getsource(raw_context)
    assert "execution-owned" not in source
    assert hasattr(raw_context, "inmemory_raw_scan_dependencies")
    assert hasattr(raw_context, "execute_inmemory_raw_stage_job")


def test_deleted_execution_owned_support_surfaces_absent():
    assert not hasattr(execution_pkg, "process_queue_support")
    assert not hasattr(execution_pkg, "inmemory_raw_dependency_factory")


import Virus_Scan.scheduler.runtime.backpressure_policy as backpressure_policy


def test_backpressure_policy_is_runtime_owned_not_execution_owned():
    assert Path(backpressure_policy.__file__).parts[-3:] == ("scheduler", "runtime", "backpressure_policy.py")
    source = inspect.getsource(backpressure_policy)
    assert "scheduler.execution" not in source
    assert hasattr(backpressure_policy, "dynamic_process_queue_target")
    assert hasattr(backpressure_policy, "io_adjusted_elastic_target")


import Virus_Scan.scheduler.orchestration.scheduler_runner as scheduler_runner


def test_scheduler_runner_is_orchestration_owned_not_execution_owned():
    assert Path(scheduler_runner.__file__).parts[-3:] == ("scheduler", "orchestration", "scheduler_runner.py")
    assert hasattr(scheduler_runner, "run_scheduler_pipeline")
    assert not hasattr(execution_pkg, "scheduler_pipeline")
