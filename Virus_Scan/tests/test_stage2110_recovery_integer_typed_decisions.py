from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.queue import recovery_contract_support as support


def _function_returns_none_literal(function_name: str) -> list[int]:
    source_path = Path(support.__file__).resolve()
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    none_return_lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            for child in ast.walk(node):
                if isinstance(child, ast.Return) and isinstance(child.value, ast.Constant) and child.value.value is None:
                    none_return_lines.append(child.lineno)
    return none_return_lines


def test_stage2110_recovery_integer_parse_decisions_replace_hidden_none_sentinels() -> None:
    assert _function_returns_none_literal("_exact_recovery_integer_text") == []
    assert _function_returns_none_literal("_exact_recovery_integer") == []
    assert "RecoveryIntegerParseDecision" in support.__all__


def test_stage2110_recovery_integer_success_keeps_legacy_projection_with_explicit_no_issue_slot() -> None:
    value, issue = support.recovery_integer_result(" +12 ", replacement=7, field_name="retry_attempt")

    assert value == 12
    assert issue is None


def test_stage2110_recovery_integer_rejections_record_reasoned_typed_fallbacks() -> None:
    value, issue = support.recovery_integer_result("-", replacement=7, field_name="retry_attempt")

    assert value == 7
    assert issue is not None
    assert issue["error_category"] == "retry_attempt_rejected"
    assert issue["recovery_integer_replacement"] == 7
    assert issue["recovery_integer_value"] == 7


def test_stage2110_recovery_integer_missing_is_distinguished_from_rejected_text() -> None:
    value, issue = support.recovery_integer_result(None, replacement=3, field_name="retry_attempt")

    assert value == 3
    assert issue is not None
    assert issue["error_category"] == "retry_attempt_missing"


def test_stage2110_recovery_integer_bool_is_rejected_without_bool_as_int() -> None:
    value, issue = support.recovery_integer_result(True, replacement=5, field_name="retry_attempt")

    assert value == 5
    assert issue is not None
    assert issue["error_category"] == "retry_attempt_rejected"
    assert issue["value_type"] == "bool"
