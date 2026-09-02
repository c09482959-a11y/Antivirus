from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, python_files_under, read_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.internal import no_hook_diagnostics
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int, scheduler_text


class HostileScalar:
    touched = False

    def __str__(self):  # pragma: no cover - must not execute
        HostileScalar.touched = True
        raise AssertionError("str hook executed")

    def __int__(self):  # pragma: no cover - must not execute
        HostileScalar.touched = True
        raise AssertionError("int hook executed")

    def __float__(self):  # pragma: no cover - must not execute
        HostileScalar.touched = True
        raise AssertionError("float hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        HostileScalar.touched = True
        raise AssertionError("bool hook executed")


def test_scheduler_scalar_defaults_do_not_execute_caller_hooks() -> None:
    HostileScalar.touched = False
    hostile = HostileScalar()

    assert scheduler_text(hostile, replacement_text="owned", unsupported_reason="text_rejected") == (
        "owned",
        "text_rejected",
    )
    assert scheduler_int(hostile, default=7, minimum=1, reason="int_rejected") == (7, "int_rejected")
    assert scheduler_float(hostile, default=3.5, minimum=0.0, reason="float_rejected") == (
        3.5,
        "float_rejected",
    )
    assert HostileScalar.touched is False


def test_no_hook_diagnostics_public_scalar_contract_does_not_expose_fallback_parameter() -> None:
    source_path = Path(no_hook_diagnostics.__file__)
    source = read_python_file(source_path)
    tree = parse_python_file(source_path)
    checked = {"scheduler_text", "scheduler_float", "scheduler_int"}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in checked:
            keyword_names = {arg.arg for arg in node.args.kwonlyargs}
            assert "fallback" not in keyword_names
    assert "safe_fallback" not in source
    assert "fallback_value" not in source
    assert "default=fallback" not in source


def test_scheduler_call_sites_use_explicit_default_or_replacement_keywords() -> None:
    checked = {"scheduler_text", "scheduler_float", "scheduler_int"}
    for path in python_files_under("Virus_Scan/scheduler"):
        tree = parse_python_file(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            else:
                continue
            if name in checked:
                assert all(keyword.arg != "fallback" for keyword in node.keywords), str(path)
