"""Stage2010 core cache failure-boundary regressions."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.core import cache
from Virus_Scan.tests.support.scan_cache_fixtures import disabled_scan_cache_identity
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle


class _HostileCacheKey:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("cache key truth hook executed")

    def __hash__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("cache key hash hook executed")

    def __str__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("cache key str hook executed")

    def __repr__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("cache key repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("cache key format hook executed")


class _HostileCacheError(OSError):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("cache error str hook executed")

    def __repr__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("cache error repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("cache error format hook executed")


def _raise_hostile_cache_error(*_args, **_kwargs):
    raise _HostileCacheError("boom")


def _source_function(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"missing function {name}")


def test_stage2010_cache_wrappers_fail_closed_without_hostile_key_hooks() -> None:
    hostile = _HostileCacheKey()
    _HostileCacheKey.reset()

    with pytest.raises(ValueError):
        cache.cache_get({}, hostile)
    with pytest.raises(ValueError):
        cache.cache_set({}, hostile, {"ok": True})
    with pytest.raises(TypeError):
        cache.cache_get([], "owned-key")

    assert _HostileCacheKey.touched == 0


def test_stage2010_cache_maintenance_logs_exception_type_without_error_hooks() -> None:
    messages: list[str] = []
    cleared: list[tuple[str, ...]] = []
    _HostileCacheError.reset()

    original_defer = cache.BULK_DEFER_PROFILE_WRITES
    original_prune = cache.prune_graph_owned
    original_clear = cache.clear_runtime_caches
    original_log = cache.log_error
    try:
        cache.BULK_DEFER_PROFILE_WRITES = True
        cache.prune_graph_owned = _raise_hostile_cache_error
        cache.clear_runtime_caches = lambda *names: cleared.append(names)
        cache.log_error = messages.append
        cache.bulk_scan_maintenance(1000, prune_every=1000)
    finally:
        cache.BULK_DEFER_PROFILE_WRITES = original_defer
        cache.prune_graph_owned = original_prune
        cache.clear_runtime_caches = original_clear
        cache.log_error = original_log

    assert messages == ["bulk graph prune failed: _HostileCacheError"]
    assert cleared == [("GRAPH_RISK_CACHE", "RISK_CACHE", "MARKOV_CACHE")]
    assert _HostileCacheError.touched == 0


def test_stage2010_passive_asset_hint_failure_is_not_false_sentinel(tmp_path: Path) -> None:
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"not-media")
    _HostileCacheError.reset()

    snapshot = artifact_read_snapshot_fixture(sample)
    original_open = Path.open
    try:
        Path.open = _raise_hostile_cache_error
        assert cache._umige_passive_asset_cache_hint(snapshot) is False
    finally:
        Path.open = original_open

    assert _HostileCacheError.touched == 0


def test_stage2010_pre_scan_cache_lookup_rejects_non_snapshot_without_error_hooks(tmp_path: Path) -> None:
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"not-media")
    messages: list[str] = []
    repository = scan_cache_repository()
    repository.configure(tmp_path / "profiles", enabled=True)
    original_log = cache.log_error
    try:
        cache.log_error = messages.append
        with pytest.raises(TypeError, match="artifact_read_snapshot_required"):
            cache.pre_scan_cache_lookup(
                str(sample), execution_identity=disabled_scan_cache_identity(),
            )
    finally:
        cache.log_error = original_log
        repository.configure(tmp_path / "disabled", enabled=False)
        sqlite_lifecycle().close()

    assert messages == []

def test_stage2010_cache_exception_handlers_have_no_hookable_formatting_or_default_returns() -> None:
    source = Path(cache.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for name in (
        "bulk_scan_maintenance",
        "cache_get",
        "cache_set",
        "_umige_passive_asset_cache_hint",
        "pre_scan_cache_lookup",
    ):
        function = _source_function(tree, name)
        for handler in (node for node in ast.walk(function) if isinstance(node, ast.ExceptHandler)):
            assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(handler))
            assert not any(isinstance(node, ast.Return) for node in ast.walk(handler))

    for forbidden in (
        "bulk graph prune failed: {e}",
        "cache_get failed: {e}",
        "cache_set failed: {e}",
        "pre-scan cache lookup failed for {path}: {e}",
    ):
        assert forbidden not in source
