from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from Virus_Scan.publication.json_finalization.base_projection import (
    canonical_chain_list,
    canonical_tag_list,
    canonical_text_list,
)

_BASE_PROJECTION_PATH = Path(__file__).resolve().parents[2] / "Virus_Scan/publication/json_finalization/base_projection.py"


class HostileCanonicalListValue:
    touched = 0

    def __iter__(self):  # pragma: no cover - failure proves iteration returned
        type(self).touched += 1
        raise AssertionError("canonical list boundary iterated unknown object")

    def __str__(self):  # pragma: no cover - failure proves string hook returned
        type(self).touched += 1
        raise AssertionError("canonical list boundary stringified unknown object")

    def __repr__(self):  # pragma: no cover - failure proves repr hook returned
        type(self).touched += 1
        raise AssertionError("canonical list boundary repr'd unknown object")


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


def _empty_list_returns(function_name: str) -> list[int]:
    tree = ast.parse(_BASE_PROJECTION_PATH.read_text(encoding="utf-8"), filename=str(_BASE_PROJECTION_PATH))
    visitor = _ReturnVisitor(function_name)
    visitor.visit(tree)
    return visitor.empty_list_returns


def test_stage1718_canonical_tag_and_chain_lists_keep_legitimate_empty_containers() -> None:
    for value in ([], (), set(), frozenset()):
        assert canonical_tag_list(value) == []
        assert canonical_chain_list(value) == []


def test_stage1718_canonical_text_list_keeps_legitimate_empty_absence() -> None:
    for value in (None, [], (), set(), frozenset()):
        assert canonical_text_list(value) == []


def test_stage1718_canonical_list_unsupported_objects_remain_explicit_without_hooks() -> None:
    HostileCanonicalListValue.touched = 0
    value: Any = HostileCanonicalListValue()

    assert canonical_tag_list(value) == ["<HostileCanonicalListValue final_json_text_unavailable>"]
    assert canonical_chain_list(value) == ["<HostileCanonicalListValue final_json_text_unavailable>"]
    projected = canonical_text_list(value)

    assert projected[0]["model_signal_projection_failed"] is True
    assert projected[0]["reason"] == "final_json_text_unavailable"
    assert HostileCanonicalListValue.touched == 0


def test_stage1718_canonical_list_functions_do_not_emit_literal_empty_return_branches() -> None:
    assert _empty_list_returns("canonical_tag_list") == []
    assert _empty_list_returns("canonical_chain_list") == []
    assert _empty_list_returns("canonical_text_list") == []
