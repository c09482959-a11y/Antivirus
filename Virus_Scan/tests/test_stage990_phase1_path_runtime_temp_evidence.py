import ast
from pathlib import Path


def _function_node(module_path: Path, function_name: str) -> ast.FunctionDef:
    tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            return node
    raise AssertionError(f"{function_name} not found")


def test_runtime_temp_dir_owner_failure_records_evidence_before_fallback():
    node = _function_node(Path("Virus_Scan/core/paths.py"), "_umige_runtime_temp_dir")
    evidence_calls = []
    clean_bare_except = []
    for try_node in (n for n in ast.walk(node) if isinstance(n, ast.Try)):
        for handler in try_node.handlers:
            if handler.type is None:
                clean_bare_except.append(handler.lineno)
            for call in (n for n in ast.walk(handler) if isinstance(n, ast.Call)):
                if isinstance(call.func, ast.Name) and call.func.id == "record_suppressed_failure":
                    if call.args and isinstance(call.args[0], ast.Constant):
                        evidence_calls.append(call.args[0].value)
    assert not clean_bare_except
    assert "runtime_temp_dir_owner_failed" in evidence_calls
