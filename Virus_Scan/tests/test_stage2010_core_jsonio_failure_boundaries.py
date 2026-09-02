"""Stage2010 core jsonio failure-boundary regressions."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from Virus_Scan.core import jsonio


class _HostileJsonError(OSError):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("json error str hook executed")

    def __repr__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("json error repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("json error format hook executed")


class _HostileContext:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("context str hook executed")

    def __repr__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("context repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("context format hook executed")


class _HostileDict(dict):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def keys(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("dict subclass keys hook executed")

    def items(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("dict subclass items hook executed")

    def __iter__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("dict subclass iter hook executed")




def test_stage2010_persistent_record_context_rejects_hostile_context_without_hooks() -> None:
    _HostileContext.reset()

    with pytest.raises(TypeError) as exc_info:
        jsonio.validate_persistent_record_semantics(object(), context=_HostileContext())

    assert "jsonio_context_rejected:_HostileContext" in str(exc_info.value)
    assert _HostileContext.touched == 0


def test_stage2010_jsonio_no_longer_owns_persistent_scan_cache() -> None:
    source = Path(jsonio.__file__).read_text(encoding="utf-8")

    assert not hasattr(jsonio, "SCAN_CACHE")
    assert not hasattr(jsonio, "load_scan_cache")
    assert not hasattr(jsonio, "flush_scan_cache")
    assert "scan_cache.json" not in source


def test_stage2010_download_meta_atomic_failure_records_without_exception_hooks(tmp_path: Path) -> None:
    messages: list[str] = []
    degraded: list[tuple[str, str, str]] = []
    _HostileJsonError.reset()

    def _record(where, exc, *, domain="persistence"):
        degraded.append((where, type(exc).__name__, domain))
        return {"recorded": True}

    original_record = jsonio._jsonio_record_degraded
    original_log = jsonio.log_error
    try:
        jsonio._jsonio_record_degraded = _record
        jsonio.log_error = messages.append
        ok = jsonio._write_download_meta(
            tmp_path / "rules.zip",
            {"checked_at": 1},
            download_meta_path=lambda _dest: str(tmp_path / "rules.zip.meta.json"),
            atomic_json_save_func=lambda *_args, **_kwargs: (_ for _ in ()).throw(_HostileJsonError("boom")),
        )
    finally:
        jsonio._jsonio_record_degraded = original_record
        jsonio.log_error = original_log

    assert ok is False
    assert degraded == [("yara_download_meta_write_failed", "_HostileJsonError", "yara")]
    assert messages == ["YARA download metadata save skipped: _HostileJsonError"]
    assert _HostileJsonError.touched == 0


def test_stage2010_jsonio_source_has_no_repaired_hookable_patterns() -> None:
    source = Path(jsonio.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert "f'" not in source
    assert 'f"' not in source
    assert "fallback" not in source
    assert ".keys()" not in source
    assert ".items()" not in source
    assert "_jsonio_safe_text(" in source
    assert "default=" not in source.split("def _jsonio_safe_text", 1)[1].split("def _jsonio_unsupported_value", 1)[0]
    guarded = {
        "_jsonio_record_degraded",
        "_jsonio_log_degraded",
        "_jsonio_stdlib_path_text",
        "_record_process_queue_failure",
        "_quarantine_corrupt_json_file",
        "_write_download_meta",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in guarded:
            for handler in [child for child in ast.walk(node) if isinstance(child, ast.ExceptHandler)]:
                assert not any(isinstance(child, ast.Return) for child in ast.walk(handler)), node.name
