from Virus_Scan.tests.support.static_inventory import parse_python_file, python_files_under, read_python_file

from pathlib import Path
import ast


ROOT = Path(__file__).resolve().parents[1]
SCHEDULER = ROOT / "scheduler"


def test_stage834_dead_scheduler_marker_surfaces_are_deleted():
    removed = (
        SCHEDULER / "ownership" / "claim_registry.py",
        SCHEDULER / "runtime" / "resource_limits.py",
        SCHEDULER / "runtime" / "freeze_runtime.py",
        SCHEDULER / "api" / "public_results.py",
        SCHEDULER / "execution" / "stage_parallel.py",
        SCHEDULER / "internal" / "validation.py",
        SCHEDULER / "ownership" / "claim_validation.py",
        SCHEDULER / "queue" / "inmemory_retry_recovery_evidence.py",
        SCHEDULER / "queue" / "raw_queue_monitor.py",
    )
    for path in removed:
        assert not path.exists(), f"dead scheduler surface still present: {path}"


def test_stage834_no_scheduler_function_imports_or_runtime_imports():
    findings = []
    for path in python_files_under("Virus_Scan/scheduler"):
        tree = parse_python_file(path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, (ast.Import, ast.ImportFrom)):
                        findings.append((path.relative_to(ROOT), node.name, getattr(child, "lineno", None)))
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in {"__import__", "exec", "eval"}:
                    findings.append((path.relative_to(ROOT), func.id, getattr(node, "lineno", None)))
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                    if func.value.id == "importlib":
                        findings.append((path.relative_to(ROOT), "importlib", getattr(node, "lineno", None)))
    assert findings == []


def test_stage834_no_oversized_scheduler_modules():
    oversized = []
    for path in python_files_under("Virus_Scan/scheduler"):
        line_count = len(read_python_file(path).splitlines())
        if line_count >= 200:
            oversized.append((path.relative_to(ROOT), line_count))
    assert oversized == []
