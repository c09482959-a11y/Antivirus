"""Stage2010 core path failure-boundary regressions."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.core import paths
from Virus_Scan.core.path_utils import core_path_text, safe_child_path


class _HostileText:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("text str hook executed")

    def __repr__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("text repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("text format hook executed")

    def __bool__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("text bool hook executed")

    def __fspath__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("path fspath hook executed")


class _HostileMapping:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def items(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("mapping items hook executed")

    def __iter__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("mapping iter hook executed")

    def __bool__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("mapping bool hook executed")


class _FakeScanIntegrity:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def set(self, key: str, value: dict[str, object]) -> None:
        self.calls.append((key, value))


def test_stage2010_core_path_text_rejects_hostile_field_name_without_hooks() -> None:
    _HostileText.reset()

    text, reason = core_path_text(object(), field_name=_HostileText())

    assert text == ""
    assert reason == "path_rejected"
    assert _HostileText.touched == 0


def test_stage2010_runtime_library_helpers_reject_hostile_path_and_text_without_hooks() -> None:
    _HostileText.reset()
    hostile_path = _HostileText()
    hostile_text = _HostileText()

    assert paths.is_known_python_runtime_library_path(hostile_path, hostile_text) is False
    assert paths.is_python_runtime_binary_path(hostile_path) is False
    assert paths.is_renpy_engine_runtime_source_path(hostile_path, hostile_text) is False
    assert paths.is_renpy_official_updater_path(hostile_path, hostile_text) is False
    assert paths.is_runtime_or_engine_library_path(hostile_path) is False

    assert _HostileText.touched == 0


def test_stage2010_scan_integrity_meta_rejects_hostile_mapping_without_hooks(tmp_path: Path) -> None:
    fake = _FakeScanIntegrity()
    _HostileMapping.reset()

    original_scan_integrity_state = paths.scan_integrity_state
    try:
        paths.scan_integrity_state = lambda: fake
        paths._set_scan_integrity(tmp_path / "sample.bin", _HostileMapping())
    finally:
        paths.scan_integrity_state = original_scan_integrity_state

    assert fake.calls
    assert fake.calls[0][1]["unavailable_reason"] == "scan_integrity_meta_rejected"
    assert fake.calls[0][1]["value_type"] == "_HostileMapping"
    assert _HostileMapping.touched == 0


def test_stage2010_safe_child_path_source_has_no_exception_sentinel_return() -> None:
    assert safe_child_path(Path("."), "../outside") is None

    source = Path(paths.__file__).with_name("path_utils.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(tree))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in {"safe_child_path", "core_path_text"}:
            for handler in [child for child in ast.walk(node) if isinstance(child, ast.ExceptHandler)]:
                assert not any(isinstance(child, ast.Return) for child in ast.walk(handler)), node.name


def test_stage2010_core_paths_source_has_no_repaired_path_patterns() -> None:
    source = Path(paths.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(tree))
    assert "getattr(" not in source
    assert "str(raw)" not in source
    assert "vars(args)" not in source
    assert "legacy-facing helper" not in source
    assert "dict(meta or {})" not in source
    assert ".values()" not in source

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for handler in [child for child in ast.walk(node) if isinstance(child, ast.ExceptHandler)]:
                assert not any(isinstance(child, ast.Return) for child in ast.walk(handler)), node.name
