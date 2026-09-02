from __future__ import annotations

from Virus_Scan.runtime import structured_failures

import ast
from pathlib import Path


CLEAN_LITERAL_NODES = (ast.Dict, ast.List, ast.Set, ast.Tuple)


def _is_clean_default_return(value: ast.AST | None) -> bool:
    if value is None:
        return True
    if isinstance(value, ast.Constant):
        return value.value in {None, False, 0, 0.0, ""}
    if isinstance(value, CLEAN_LITERAL_NODES):
        if isinstance(value, ast.Dict):
            return len(value.keys) == 0
        return len(value.elts) == 0
    return False


def test_stage968_structured_failure_broad_handlers_do_not_return_clean_defaults():
    path = Path("Virus_Scan/runtime/structured_failures.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        caught = "bare" if node.type is None else ast.unparse(node.type)
        if caught not in {"bare", "Exception", "BaseException"}:
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and _is_clean_default_return(child.value):
                findings.append((child.lineno, caught))

    assert findings == []


def test_stage968_trace_tail_formatting_failure_is_not_empty():

    structured_failures.clear_failure_records()

    def _broken_format_exception(*args, **kwargs):
        raise RuntimeError("trace formatting unavailable")

    try:
        raise ValueError("boom")
    except ValueError as exc:
        record = structured_failures.record_failure(
            "runtime",
            "trace_tail_boundary",
            exc,
            trace_formatter=_broken_format_exception,
        )

    assert record.trace_tail == "trace_unavailable:RuntimeError"
    assert any("failure_trace_tail:RuntimeError" in item for item in structured_failures.failure_recorder_internal_errors())
