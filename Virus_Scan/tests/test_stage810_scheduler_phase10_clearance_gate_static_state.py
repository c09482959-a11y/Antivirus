from pathlib import Path
import ast


SCHEDULER_ROOT = Path(__file__).resolve().parents[1] / "scheduler"


def _scheduler_python_files():
    return sorted(path for path in SCHEDULER_ROOT.rglob("*.py") if path.is_file())


def test_stage810_phase10_has_no_oversized_scheduler_modules():
    oversized = []
    near_threshold = []
    for path in _scheduler_python_files():
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        if line_count > 200:
            oversized.append((path.relative_to(SCHEDULER_ROOT), line_count))
        elif line_count >= 180:
            near_threshold.append((path.relative_to(SCHEDULER_ROOT), line_count))

    assert not oversized
    # Phase 10 clearance allows reviewed near-threshold files, but the gate
    # requires that no module remains over the roughly-200-line review target.
    assert all(line_count <= 200 for _, line_count in near_threshold)


def test_stage810_phase10_scheduler_keeps_static_module_level_imports():
    function_imports = []
    dynamic_imports = []
    for path in _scheduler_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                child.parent = node
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)) and isinstance(
                getattr(node, "parent", None), (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                function_imports.append((path.relative_to(SCHEDULER_ROOT), node.lineno))
            if isinstance(node, ast.Call):
                func = node.func
                name = ""
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    if isinstance(func.value, ast.Name):
                        name = f"{func.value.id}.{func.attr}"
                    else:
                        name = func.attr
                if name == "__import__" or name.startswith("importlib."):
                    dynamic_imports.append((path.relative_to(SCHEDULER_ROOT), node.lineno, name))

    assert not function_imports
    assert not dynamic_imports


def test_stage810_phase10_high_priority_split_targets_are_bounded():
    targets = [
        "execution/process_queue_runner.py",
        "execution/inmemory_longlived_queue.py",
        "execution/scheduler_pipeline.py",
        "reconciliation/process_queue_recovery.py",
        "reconciliation/phase_output_contracts.py",
        "ownership/workload_queues.py",
        "ownership/queue_authority.py",
        "execution/heartbeat.py",
        "execution/raw_queue_file_retry.py",
        "reconciliation/raw_queue_results.py",
    ]
    remaining = []
    for rel in targets:
        path = SCHEDULER_ROOT / rel
        if path.exists():
            remaining.append((rel, len(path.read_text(encoding="utf-8").splitlines())))

    assert all(line_count <= 200 for _, line_count in remaining)


def test_stage810_phase10_scheduler_has_no_mutable_module_level_static_state():
    mutable_globals = []
    bad_all_exports = []
    for path in _scheduler_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.iter_child_nodes(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = getattr(node, "value", None)
            targets = []
            if isinstance(node, ast.Assign):
                targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
            elif isinstance(node.target, ast.Name):
                targets = [node.target.id]
            if isinstance(value, (ast.List, ast.Dict, ast.Set)):
                mutable_globals.append((path.relative_to(SCHEDULER_ROOT), node.lineno, tuple(targets)))
            if "__all__" in targets and not isinstance(value, ast.Tuple):
                bad_all_exports.append((path.relative_to(SCHEDULER_ROOT), node.lineno))

    assert not mutable_globals
    assert not bad_all_exports
