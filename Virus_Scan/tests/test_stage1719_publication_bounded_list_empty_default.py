from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from Virus_Scan.publication.json_finalization.base_projection import bounded_list

_BASE_PROJECTION_PATH = Path(__file__).resolve().parents[2] / "Virus_Scan/publication/json_finalization/base_projection.py"


class HostileBoundedListValue:
    touched = 0

    def __iter__(self):  # pragma: no cover - failure proves iteration returned
        type(self).touched += 1
        raise AssertionError("bounded_list iterated unknown object")

    def __str__(self):  # pragma: no cover - failure proves string hook returned
        type(self).touched += 1
        raise AssertionError("bounded_list stringified unknown object")

    def __repr__(self):  # pragma: no cover - failure proves repr hook returned
        type(self).touched += 1
        raise AssertionError("bounded_list repr'd unknown object")


class _ReturnVisitor(ast.NodeVisitor):
    def __init__(self, target: str) -> None:
        self.target = target
        self.in_target = False
        self.empty_list_returns: list[int] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous = self.in_target
        self.in_target = node.name == self.target
        self.generic_visit(node)
        self.in_target = previous

    def visit_Return(self, node: ast.Return) -> None:
        if self.in_target and isinstance(node.value, ast.List) and not node.value.elts:
            self.empty_list_returns.append(node.lineno)
        self.generic_visit(node)


def test_stage1719_bounded_list_keeps_legitimate_missing_list_empty() -> None:
    assert bounded_list(None) == []


def test_stage1719_bounded_list_unsupported_object_is_explicit_without_hooks() -> None:
    HostileBoundedListValue.touched = 0
    projected = bounded_list(HostileBoundedListValue())

    assert projected[0]["model_signal_projection_failed"] is True
    assert projected[0]["reason"] == "final_json_list_value_unavailable"
    assert HostileBoundedListValue.touched == 0


def test_stage1719_bounded_list_has_no_literal_empty_return_branch() -> None:
    tree = ast.parse(_BASE_PROJECTION_PATH.read_text(encoding="utf-8"), filename=str(_BASE_PROJECTION_PATH))
    visitor = _ReturnVisitor("bounded_list")
    visitor.visit(tree)

    assert visitor.empty_list_returns == []
