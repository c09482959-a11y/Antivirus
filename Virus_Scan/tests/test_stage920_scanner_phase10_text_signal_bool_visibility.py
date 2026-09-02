
"""Stage 920 Phase 10: binary text signal helpers reject caller-owned text hooks."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners.binary_text_signals import binary_text_has_any


class _HostileText:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


def test_hostile_text_object_content_is_rejected_without_hooks() -> None:
    _HostileText.touched = 0

    assert binary_text_has_any(_HostileText(), ["powershell"]) is False
    assert _HostileText.touched == 0


def test_binary_text_signal_does_not_use_boolean_default_for_haystack() -> None:
    source = read_python_file(Path("Virus_Scan/scanners/binary_text_signals.py"))
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.BoolOp):
            assert not any(
                isinstance(value, ast.Name) and value.id == "text"
                for value in node.values
            ), "text input should not be boolean-coerced into a clean empty string"
