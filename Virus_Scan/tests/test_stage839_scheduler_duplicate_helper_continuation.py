from Virus_Scan.tests.support.static_inventory import parse_python_file, python_files_under, read_python_file

import ast
import inspect
from pathlib import Path


from Virus_Scan.scheduler.context import inmemory_raw_dependency_factory as raw_factory
from Virus_Scan.scheduler.context import inmemory_raw_policy_dependencies as raw_policy
from Virus_Scan.scheduler.timeout import timeout_budget
from Virus_Scan.scheduler.timeout import timeout_workload_inspection as inspection


def test_stage839_raw_dependency_factory_uses_policy_owned_helpers_without_duplicate_bodies():
    source = inspect.getsource(raw_factory)
    duplicated_function_names = [
        "_record_process_queue_suppressed",
        "_record_raw_queue_issue",
        "_raw_chunk_bytes",
        "_raw_queue_max_chunks",
        "_raw_queue_enabled",
        "_raw_queue_min_bytes",
        "_raw_collector_cap",
    ]
    for name in duplicated_function_names:
        assert f"def {name}" not in source
    assert raw_factory._record_process_queue_suppressed is raw_policy.record_process_queue_suppressed
    assert raw_factory._record_raw_queue_issue is raw_policy.record_raw_queue_issue
    assert raw_factory._raw_chunk_bytes is raw_policy.raw_chunk_bytes
    assert raw_factory._raw_queue_enabled is raw_policy.raw_queue_enabled
    assert raw_factory._retry_max is raw_policy.retry_max


def test_stage839_timeout_budget_imports_public_inspection_contracts_only():
    source = inspect.getsource(timeout_budget)
    assert "timeout_workload_inspection import archive_metrics, image_pixel_count" in source
    assert "timeout_workload_inspection import _" not in source
    assert callable(inspection.archive_metrics)
    assert callable(inspection.image_pixel_count)
    assert set(inspection.__all__) == {"archive_metrics", "image_pixel_count"}


def test_stage839_no_scheduler_module_imports_private_timeout_inspection_helpers():
    findings = []
    root = Path("Virus_Scan/scheduler")
    target_module = "Virus_Scan.scheduler.timeout.timeout_workload_inspection"
    for path in python_files_under("Virus_Scan/scheduler"):
        source = read_python_file(path)
        if target_module not in source:
            continue
        tree = parse_python_file(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if node.module != "Virus_Scan.scheduler.timeout.timeout_workload_inspection":
                continue
            private_names = [alias.name for alias in node.names if alias.name.startswith("_")]
            if private_names:
                findings.append(f"{path}:{node.lineno}:{private_names}")
    assert findings == []
