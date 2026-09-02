import ast
from pathlib import Path

from Virus_Scan.scheduler.orchestration.inmemory_parent_loop import _run_longlived_process_queue
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture


LOOP_MODULE = Path("Virus_Scan/scheduler/orchestration/inmemory_parent_loop.py")
ITERATION_MODULE = Path("Virus_Scan/scheduler/orchestration/inmemory_parent_iteration.py")


def _function_lengths(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name: node.end_lineno - node.lineno + 1
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def test_inmemory_parent_loop_public_behavior_and_function_bounds_are_preserved():
    loop_lengths = _function_lengths(LOOP_MODULE)
    iteration_lengths = _function_lengths(ITERATION_MODULE)
    assert callable(_run_longlived_process_queue)
    assert _run_longlived_process_queue(
        "/tmp", [], 1, result_retainer=lambda _path, result: result,
        derived_cache_writer=lambda _result: False,
        scan_session_snapshot=scan_session_snapshot_fixture(scan_mode="process"),
    ) == {}
    assert loop_lengths["_run_longlived_process_queue"] <= 75
    assert all(length <= 75 for length in loop_lengths.values())
    assert all(length <= 75 for length in iteration_lengths.values())
    assert len(LOOP_MODULE.read_text(encoding="utf-8").splitlines()) <= 200
    assert len(ITERATION_MODULE.read_text(encoding="utf-8").splitlines()) <= 200


def test_inmemory_parent_loop_delegates_iteration_ownership_to_bounded_module():
    loop_text = LOOP_MODULE.read_text(encoding="utf-8")
    iteration_text = ITERATION_MODULE.read_text(encoding="utf-8")
    required_helpers = {
        "dispatch_longlived_parent_jobs",
        "handle_next_inmemory_parent_result_iteration",
        "run_inmemory_respawn_sweep_iteration",
        "run_inmemory_parent_maintenance_iteration",
        "reconcile_or_wait_for_empty_drain",
    }
    for helper in required_helpers:
        assert helper in loop_text
        assert f"def {helper}" in iteration_text
    assert "build_inmemory_parent_runtime" in loop_text
    assert "handle_next_inmemory_parent_result" in loop_text
    assert "run_inmemory_respawn_sweep" in loop_text
    assert "run_inmemory_parent_maintenance" in loop_text
    assert "enforce_inmemory_timeout_sweep" not in loop_text


def test_inmemory_parent_loop_keeps_static_import_ownership():
    for module in (LOOP_MODULE, ITERATION_MODULE):
        text = module.read_text(encoding="utf-8")
        tree = ast.parse(text)
        function_local_imports = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, (ast.Import, ast.ImportFrom)):
                        function_local_imports.append((node.name, child.lineno))
        assert function_local_imports == []
        assert "importlib" not in text
