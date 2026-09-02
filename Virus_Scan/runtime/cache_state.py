"""Canonical cache mutation boundary for Phase C shared-state collapse.

The scanner historically exposed several runtime caches as module globals and
mutated them directly from maintenance, model, and scanner paths.  This module
keeps the existing cache dictionaries as the single storage objects for parity,
but all mutation goes through this owner so cache clear/get/set/prune behavior is
lock-protected, auditable, and not duplicated through shared STATE snapshots.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from threading import RLock
from time import time
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_text,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value, materialize_runtime_value

if TYPE_CHECKING:
    from collections.abc import MutableMapping

def _cache_owner_message(prefix: str, key: str) -> str:
    return str.__add__(prefix, key)


def _validated_cache_name(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="runtime_cache_name_missing",
        unsupported_reason="runtime_cache_name_rejected",
    )
    if reason or text == "":
        raise ValueError(reason or "runtime_cache_name_blank")
    return text


def _cache_key(value: object) -> object:
    if value is None or type(value) in (bool, int, bytes):
        return value
    if isinstance(value, str):
        return str.__str__(value)
    if type(value) is float:
        metric, reason = no_hook_finite_float(value, reason="runtime_cache_key_rejected")
        if not reason:
            return metric
    if type(value) is tuple:
        return tuple(_cache_key(item) for item in value)
    raise ValueError("runtime_cache_key_rejected")


def _cache_limit(value: object) -> int:
    limit, reason = no_hook_exact_nonnegative_int(
        value, default=0, reason="runtime_cache_limit_rejected"
    )
    if reason:
        raise ValueError(reason)
    return limit


def _cache_timestamp(value: object) -> float:
    timestamp, reason = no_hook_finite_float(
        value,
        default=0.0,
        minimum=0.0,
        reason="runtime_cache_timestamp_rejected",
    )
    return 0.0 if reason else timestamp


def _cache_value_copy(value: object) -> object:
    return materialize_runtime_value(freeze_runtime_value(value))


class CacheStateOwner:
    """Single mutation authority for runtime cache dictionaries."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._named: dict[str, MutableMapping[object, object]] = {}

    @property
    def lock(self) -> RLock:
        return self._lock

    def register(self, name: str, mapping: MutableMapping[object, object] | None) -> MutableMapping[object, object] | None:
        if mapping is None:
            return None
        if type(mapping) is not dict:
            exception_message = "cache owner registration requires exact mutable mapping"
            raise TypeError(exception_message)
        key = _validated_cache_name(name)
        with self._lock:
            existing = self._named.get(key)
            if existing is not None and existing is not mapping:
                raise RuntimeError(_cache_owner_message("runtime cache registration drift for ", key))
            self._named[key] = mapping
        return mapping

    def clear(self, *names: str) -> None:
        with self._lock:
            selected = names if len(names) > 0 else tuple(dict.keys(self._named))
            for name in selected:
                cache = dict.get(self._named, _validated_cache_name(name))
                if cache is not None:
                    dict.clear(cache)

    def get(self, cache: MutableMapping[object, object], key: object, *, ttl: float | None = None) -> object:
        if type(cache) is not dict:
            exception_message = "runtime cache mapping rejected"
            raise TypeError(exception_message)
        safe_key = _cache_key(key)
        with self._lock:
            item = dict.get(cache, safe_key)
            if item is None:
                return None
            if ttl is not None and type(item) is tuple and len(item) == 2:
                ts, value = item
                ttl_value, ttl_reason = no_hook_finite_float(
                    ttl,
                    default=0.0,
                    minimum=0.0,
                    reason="runtime_cache_ttl_rejected",
                )
                if ttl_reason:
                    raise ValueError(ttl_reason)
                if time() - _cache_timestamp(ts) <= ttl_value:
                    return _cache_value_copy(value)
                dict.pop(cache, safe_key, None)
                return None
            if type(item) is tuple and len(item) == 2:
                return _cache_value_copy(item[1])
            return _cache_value_copy(item)

    def set(self, cache: MutableMapping[object, object], key: object, value: object, *, max_items: int | None = None) -> object:
        if type(cache) is not dict:
            exception_message = "runtime cache mapping rejected"
            raise TypeError(exception_message)
        safe_key = _cache_key(key)
        stored_value = _cache_value_copy(value)
        with self._lock:
            dict.__setitem__(cache, safe_key, (time(), stored_value))
            limit = 0 if max_items is None else _cache_limit(max_items)
            if limit and len(cache) > limit:
                ranked: list[tuple[object, object]] = sorted(
                    cache.items(),
                    key=lambda kv: _cache_timestamp(kv[1][0]) if type(kv[1]) is tuple and kv[1] else 0.0,
                    reverse=True,
                )[:limit]
                dict.clear(cache)
                dict.update(cache, dict(ranked))
        return _cache_value_copy(stored_value)

    def get_named(self, name: str) -> MutableMapping[object, object]:
        key = _validated_cache_name(name)
        with self._lock:
            cache = self._named.get(key)
        if cache is None:
            raise KeyError(_cache_owner_message("runtime cache is not registered: ", key))
        return cache

    def prune(self, *, max_items: int) -> None:
        limit = _cache_limit(max_items)
        if limit <= 0:
            return
        with self._lock:
            for cache in tuple(dict.values(self._named)):
                if len(cache) <= limit:
                    continue
                ranked: list[tuple[object, object]] = sorted(
                    cache.items(),
                    key=lambda kv: _cache_timestamp(kv[1][0]) if type(kv[1]) is tuple and kv[1] else 0.0,
                    reverse=True,
                )[:limit]
                dict.clear(cache)
                dict.update(cache, dict(ranked))

    def snapshot(self) -> MappingProxyType:
        with self._lock:
            return MappingProxyType({name: len(cache) for name, cache in tuple(dict.items(self._named))})


_CACHE_STATE = CacheStateOwner()

_DEFAULT_RUNTIME_CACHE_NAMES = (
    'GRAPH_RISK_CACHE', 'RISK_CACHE', 'MARKOV_CACHE', 'TEMPORAL_CACHE',
    'GRAPH_PROPAGATION_CACHE', 'GRAPH_ATTENTION_CACHE', 'EVASION_CACHE', 'CACHE_STORE',
)
for _cache_name in _DEFAULT_RUNTIME_CACHE_NAMES:
    _CACHE_STATE.register(_cache_name, {})

def clear_runtime_caches(*names: str) -> None:
    _CACHE_STATE.clear(*names)


def runtime_cache_get(cache: MutableMapping[object, object], key: object, *, ttl: float | None = None) -> object:
    return _CACHE_STATE.get(cache, key, ttl=ttl)


def runtime_cache_set(cache: MutableMapping[object, object], key: object, value: object, *, max_items: int | None = None) -> object:
    return _CACHE_STATE.set(cache, key, value, max_items=max_items)



def runtime_cache_by_name(name: str) -> MutableMapping[object, object]:
    """Return a registered runtime cache by owner name.

    This keeps scanner/core callers on the cache-state owner
    only to reach mutable cache dictionaries.  Missing caches are owner-contract
    defects and are surfaced immediately rather than creating detached alternate
    dictionaries.
    """
    return _CACHE_STATE.get_named(name)


def prune_runtime_caches_for_retention(*, max_items: int) -> None:
    """Bound all registered runtime caches through the cache-state owner."""
    _CACHE_STATE.prune(max_items=max_items)


__all__ = (
    'CacheStateOwner',
    'clear_runtime_caches',
    'prune_runtime_caches_for_retention',
    'runtime_cache_by_name',
    'runtime_cache_get',
    'runtime_cache_set',
)
