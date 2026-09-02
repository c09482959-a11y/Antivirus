from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.internal import owned_indexed_sequence
from Virus_Scan.scheduler.internal.owned_indexed_sequence import (
    is_owned_indexed_sequence,
    owned_indexed_sequence_decision,
    owned_indexed_sequence_rejection_reason,
)


class HostileIndexed:
    touched = False

    def __len__(self):  # pragma: no cover - must not execute
        HostileIndexed.touched = True
        raise AssertionError("len hook executed")

    def __getitem__(self, index):  # pragma: no cover - must not execute
        HostileIndexed.touched = True
        raise AssertionError(index)


def test_owned_indexed_sequence_decision_preserves_builtin_compatibility() -> None:
    list_decision = owned_indexed_sequence_decision([1, 2], writable=True)
    assert list_decision.is_owned is True
    assert list_decision.rejection_reason == ""
    assert list_decision.accepted_type == "builtin_list"
    assert is_owned_indexed_sequence([1, 2], writable=True) is True
    assert owned_indexed_sequence_rejection_reason([1, 2], writable=True) == ""

    tuple_decision = owned_indexed_sequence_decision((1, 2), writable=False)
    assert tuple_decision.is_owned is True
    assert tuple_decision.rejection_reason == ""
    assert tuple_decision.accepted_type == "builtin_tuple_readonly"
    assert is_owned_indexed_sequence((1, 2), writable=False) is True


def test_owned_indexed_sequence_decision_replays_rejection_reason_without_hooks() -> None:
    HostileIndexed.touched = False
    hostile = HostileIndexed()

    decision = owned_indexed_sequence_decision(hostile, writable=False)

    assert decision.is_owned is False
    assert decision.rejection_reason == "owned_indexed_sequence_module_rejected"
    assert decision.accepted_type == "owned_indexed_sequence_not_admitted"
    assert is_owned_indexed_sequence(hostile, writable=False) is False
    assert owned_indexed_sequence_rejection_reason(hostile, writable=False) == (
        "owned_indexed_sequence_module_rejected"
    )
    assert HostileIndexed.touched is False


def test_owned_indexed_sequence_writable_tuple_has_explicit_rejection() -> None:
    decision = owned_indexed_sequence_decision((1, 2), writable=True)

    assert decision.is_owned is False
    assert decision.rejection_reason == "owned_indexed_sequence_type_rejected"
    assert is_owned_indexed_sequence((1, 2), writable=True) is False
    assert owned_indexed_sequence_rejection_reason((1, 2), writable=True) == (
        "owned_indexed_sequence_type_rejected"
    )


def test_owned_indexed_sequence_public_wrappers_project_typed_decision() -> None:
    source = Path(owned_indexed_sequence.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    wrappers = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name
        in {
            "is_owned_indexed_sequence",
            "owned_indexed_sequence_decision",
            "owned_indexed_sequence_rejection_reason",
        }
    }

    reason_return = wrappers["owned_indexed_sequence_rejection_reason"].body[0]
    assert isinstance(reason_return, ast.Return)
    assert isinstance(reason_return.value, ast.Attribute)
    assert reason_return.value.attr == "rejection_reason"

    bool_return = wrappers["is_owned_indexed_sequence"].body[0]
    assert isinstance(bool_return, ast.Return)
    assert isinstance(bool_return.value, ast.Attribute)
    assert bool_return.value.attr == "is_owned"

    for node in ast.walk(wrappers["owned_indexed_sequence_decision"]):
        assert not (
            isinstance(node, ast.Return)
            and isinstance(node.value, ast.Constant)
            and node.value.value == ""
        )
