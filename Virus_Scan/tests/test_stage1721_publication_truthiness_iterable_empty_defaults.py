from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.publication.json_finalization.base_projection import (
    bounded_list,
    canonical_chain_list,
    canonical_tag_list,
    canonical_text_list,
)
from Virus_Scan.publication.json_finalization.truthiness import (
    any_signal_present,
    iterable_values_without_truthiness,
    signal_present,
)

_TRUTHINESS_PATH = Path(__file__).resolve().parents[2] / "Virus_Scan/publication/json_finalization/truthiness.py"


class HostileUnsupportedIterableValue:
    touched = 0

    def __iter__(self):  # pragma: no cover - failure proves unsafe iteration returned
        type(self).touched += 1
        raise AssertionError("iterable_values_without_truthiness iterated unknown object")

    def __str__(self):  # pragma: no cover - failure proves unsafe string conversion returned
        type(self).touched += 1
        raise AssertionError("iterable_values_without_truthiness stringified unknown object")

    def __repr__(self):  # pragma: no cover - failure proves unsafe repr returned
        type(self).touched += 1
        raise AssertionError("iterable_values_without_truthiness repr'd unknown object")


class HostileSignalMapping(dict):
    touched = 0

    def __len__(self):  # pragma: no cover - failure proves hostile length returned
        type(self).touched += 1
        raise AssertionError("signal_present called mapping __len__")

    def __iter__(self):  # pragma: no cover - failure proves hostile iteration returned
        type(self).touched += 1
        raise AssertionError("signal_present called mapping __iter__")

    def __bool__(self):  # pragma: no cover - failure proves hostile truthiness returned
        type(self).touched += 1
        raise AssertionError("signal_present called mapping __bool__")


class HostileSignalList(list):
    touched = 0

    def __len__(self):  # pragma: no cover - failure proves hostile length returned
        type(self).touched += 1
        raise AssertionError("signal_present called sequence __len__")

    def __iter__(self):  # pragma: no cover - failure proves hostile iteration returned
        type(self).touched += 1
        raise AssertionError("signal_present called sequence __iter__")

    def __bool__(self):  # pragma: no cover - failure proves hostile truthiness returned
        type(self).touched += 1
        raise AssertionError("signal_present called sequence __bool__")


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


def test_stage1721_iterable_values_keeps_internal_empty_absence_without_literal_return() -> None:
    assert iterable_values_without_truthiness(None) == []
    assert iterable_values_without_truthiness(()) == []
    assert iterable_values_without_truthiness([]) == []


def test_stage1721_iterable_values_unsupported_object_is_internal_empty_without_hooks() -> None:
    HostileUnsupportedIterableValue.touched = 0
    value = HostileUnsupportedIterableValue()

    assert iterable_values_without_truthiness(value) == []
    assert HostileUnsupportedIterableValue.touched == 0


def test_stage1721_publication_callers_still_emit_evidence_or_markers_for_unsupported_object() -> None:
    HostileUnsupportedIterableValue.touched = 0
    value = HostileUnsupportedIterableValue()

    list_projection = bounded_list(value)
    text_projection = canonical_text_list(value)

    assert list_projection[0]["model_signal_projection_failed"] is True
    assert list_projection[0]["reason"] == "final_json_list_value_unavailable"
    assert text_projection[0]["model_signal_projection_failed"] is True
    assert text_projection[0]["reason"] == "final_json_text_unavailable"
    assert canonical_tag_list(value) == ["<HostileUnsupportedIterableValue final_json_text_unavailable>"]
    assert canonical_chain_list(value) == ["<HostileUnsupportedIterableValue final_json_text_unavailable>"]
    assert HostileUnsupportedIterableValue.touched == 0


def test_stage1721_signal_presence_does_not_execute_container_subclass_hooks() -> None:
    HostileSignalMapping.touched = 0
    HostileSignalList.touched = 0
    mapping = HostileSignalMapping({"failure": "visible"})
    sequence = HostileSignalList(["failure"])

    assert signal_present(mapping) is True
    assert signal_present(sequence) is True
    assert any_signal_present({"evidence": mapping}, "evidence") is True
    assert signal_present({}) is False
    assert signal_present([]) is False
    assert HostileSignalMapping.touched == 0
    assert HostileSignalList.touched == 0


def test_stage1721_iterable_values_without_truthiness_has_no_literal_empty_return_branch() -> None:
    tree = ast.parse(_TRUTHINESS_PATH.read_text(encoding="utf-8"), filename=str(_TRUTHINESS_PATH))
    visitor = _ReturnVisitor("iterable_values_without_truthiness")
    visitor.visit(tree)

    assert visitor.empty_list_returns == []
