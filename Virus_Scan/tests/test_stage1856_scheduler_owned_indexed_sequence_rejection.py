from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.internal import owned_indexed_sequence
from Virus_Scan.scheduler.internal.owned_indexed_sequence import (
    is_owned_indexed_sequence,
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


def test_owned_indexed_sequence_rejects_hostile_instance_without_hooks() -> None:
    HostileIndexed.touched = False
    hostile = HostileIndexed()
    assert is_owned_indexed_sequence(hostile, writable=False) is False
    assert owned_indexed_sequence_rejection_reason(hostile, writable=False) == (
        "owned_indexed_sequence_module_rejected"
    )
    assert HostileIndexed.touched is False


def test_owned_indexed_sequence_preserves_exact_builtin_contracts() -> None:
    assert is_owned_indexed_sequence([1, 2], writable=True) is True
    assert is_owned_indexed_sequence((1, 2), writable=False) is True
    assert is_owned_indexed_sequence((1, 2), writable=True) is False
    assert owned_indexed_sequence_rejection_reason((1, 2), writable=True) == (
        "owned_indexed_sequence_type_rejected"
    )


def test_owned_indexed_sequence_no_exception_sentinel_return() -> None:
    source = Path(owned_indexed_sequence.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                for child in handler.body:
                    assert not (
                        isinstance(child, ast.Return)
                        and isinstance(child.value, ast.Constant)
                        and child.value.value is False
                    )
    assert "return False" not in source
