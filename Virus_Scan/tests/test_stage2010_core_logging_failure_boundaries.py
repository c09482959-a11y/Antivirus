"""Stage2010 core logging failure-boundary regressions."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.core import logging as core_logging


class _HostileLogError(RuntimeError):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("log error str hook executed")

    def __repr__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("log error repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("log error format hook executed")


class _HostileLogOdds:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __float__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("log odds float hook executed")

    def __str__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("log odds str hook executed")


class _HostileBinary:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bytes__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("binary bytes hook executed")

    def __len__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("binary len hook executed")

    def __getitem__(self, _key):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("binary getitem hook executed")


def test_stage2010_log_error_rejects_exception_without_text_hooks() -> None:
    messages: list[str] = []
    _HostileLogError.reset()

    original_error = core_logging.logging.error
    try:
        core_logging.logging.error = lambda msg, *args: messages.append(msg % args if args else msg)
        core_logging.log_error(_HostileLogError("boom"))
    finally:
        core_logging.logging.error = original_error

    assert messages == ["_HostileLogError"]
    assert _HostileLogError.touched == 0


def test_stage2010_log_odds_rejects_hostile_numeric_without_hooks() -> None:
    _HostileLogOdds.reset()

    try:
        core_logging.log_odds(_HostileLogOdds())
    except ValueError as exc:
        assert str(exc) == "log_odds_probability_rejected"
    else:  # pragma: no cover - test fails if reached
        raise AssertionError("hostile log odds value was accepted")

    assert _HostileLogOdds.touched == 0


def test_stage2010_raw_retry_exception_logs_without_exception_hooks(tmp_path: Path) -> None:
    messages: list[str] = []
    _HostileLogError.reset()

    original_prepare = core_logging.prepare_raw_retry_job
    original_log = core_logging.log_error
    try:
        core_logging.prepare_raw_retry_job = lambda *_args, **_kwargs: (_ for _ in ()).throw(_HostileLogError("boom"))
        core_logging.log_error = messages.append
        assert core_logging._umige_prepare_raw_retry(str(tmp_path), {}, {}) is False
    finally:
        core_logging.prepare_raw_retry_job = original_prepare
        core_logging.log_error = original_log
    assert messages == ["raw retry publish failed: _HostileLogError"]
    assert _HostileLogError.touched == 0


def test_stage2010_dotnet_pe_rejects_hostile_binary_without_hooks() -> None:
    _HostileBinary.reset()

    assert core_logging.is_dotnet_pe(_HostileBinary()) is False
    assert core_logging.is_dotnet_pe(b"MZ") is False
    assert _HostileBinary.touched == 0


def test_stage2010_core_logging_source_has_no_repaired_hookable_patterns() -> None:
    source = Path(core_logging.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(tree))
    assert "getattr(" not in source
    assert "safe_exception_message" not in source
    assert "safe_clamp(p, 1e-06" not in source
    guarded = {
        "_log_yara_download_failure_once",
        "queue_safe_unlink",
        "_umige_prepare_raw_retry",
        "configure_single_parent_log",
        "is_dotnet_pe",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in guarded:
            for handler in [child for child in ast.walk(node) if isinstance(child, ast.ExceptHandler)]:
                assert not any(isinstance(child, ast.Return) for child in ast.walk(handler)), node.name
    assert not hasattr(core_logging, "queue_atomic_replace")
