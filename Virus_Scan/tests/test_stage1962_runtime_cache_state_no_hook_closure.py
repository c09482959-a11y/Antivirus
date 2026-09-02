from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.runtime.cache_state import CacheStateOwner

RUNTIME_ROOT = Path(__file__).resolve().parents[1] / "runtime"


class Stage1962HostileName:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - failure proves unsafe string hook
        type(self).touched += 1
        raise AssertionError("hostile name str touched")

    def __repr__(self):  # pragma: no cover - failure proves unsafe repr hook
        type(self).touched += 1
        raise AssertionError("hostile name repr touched")

    def __format__(self, _spec):  # pragma: no cover - failure proves unsafe format hook
        type(self).touched += 1
        raise AssertionError("hostile name format touched")

    def __bool__(self):  # pragma: no cover - failure proves unsafe truth hook
        type(self).touched += 1
        raise AssertionError("hostile name bool touched")


class Stage1962HostileCacheKey:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile key str touched")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile key repr touched")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile key format touched")

    def __lt__(self, _other):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile key comparison touched")

    def __hash__(self):
        return 1962


def test_stage1962_runtime_cache_state_source_closes_current_backlog_routes() -> None:
    source = (RUNTIME_ROOT / "cache_state.py").read_text(encoding="utf-8")
    forbidden = (
        'f"runtime cache registration drift for',
        'f"runtime cache is not registered:',
        "selected = names if names else tuple(dict.keys(self._named))",
        "dict.items(cache),",
        "for cache in dict.values(self._named):",
        "for name, cache in dict.items(self._named)",
    )
    for snippet in forbidden:
        assert snippet not in source


def test_stage1962_runtime_cache_state_preserves_exact_drift_and_missing_messages() -> None:
    owner = CacheStateOwner()
    first: dict[object, object] = {}
    owner.register("stage1962", first)
    assert owner.register("stage1962", first) is first

    with pytest.raises(RuntimeError) as drift:
        owner.register("stage1962", {})
    assert str(drift.value) == "runtime cache registration drift for stage1962"

    with pytest.raises(KeyError) as missing:
        owner.get_named("stage1962-missing")
    assert "runtime cache is not registered: stage1962-missing" in str(missing.value)


def test_stage1962_runtime_cache_state_rejects_hostile_cache_names_without_hooks() -> None:
    Stage1962HostileName.reset()
    owner = CacheStateOwner()

    with pytest.raises(ValueError, match="runtime_cache_name_rejected"):
        owner.register(Stage1962HostileName(), {})
    with pytest.raises(ValueError, match="runtime_cache_name_rejected"):
        owner.clear(Stage1962HostileName())
    with pytest.raises(ValueError, match="runtime_cache_name_rejected"):
        owner.get_named(Stage1962HostileName())

    assert Stage1962HostileName.touched == 0


def test_stage1962_runtime_cache_state_prune_and_snapshot_do_not_touch_hostile_cache_keys() -> None:
    Stage1962HostileCacheKey.reset()
    owner = CacheStateOwner()
    hostile = Stage1962HostileCacheKey()
    cache = {hostile: (1.0, "old"), "safe": (2.0, "new")}

    owner.register("stage1962-cache", cache)
    owner.prune(max_items=1)
    snapshot = owner.snapshot()

    assert Stage1962HostileCacheKey.touched == 0
    assert snapshot["stage1962-cache"] == 1
    assert list(cache.values()) == [(2.0, "new")]
