"""Runtime-owned profile scoring snapshot state.

Runtime owns the mutable profile-scoring snapshot boundary. Model profile
learning supplies detached profile data, while detection/routing consumers read
immutable snapshots through this runtime owner. This prevents model modules from
owning process-wide mutable snapshot state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_duplicate_key,
    no_hook_failure,
    no_hook_json_key,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_type_name,
)


def _profile_state_sort_key(value: object) -> tuple[str, str]:
    materialized = no_hook_materialize(value, reason_prefix="profile_sort")
    return (no_hook_json_sort_key(materialized), no_hook_type_name(value))


def _profile_unavailable(value: object, reason: str) -> Mapping[str, object]:
    return MappingProxyType(no_hook_failure(reason, value))


def _profile_text(value: object) -> str:
    if type(value) is str:
        return str.__str__(value)
    return "profile"


def _profile_join(left: object, right: object) -> str:
    return _profile_text(left) + str.__str__(right)


def _profile_reason(reason_prefix: object, suffix: str) -> str:
    return _profile_text(reason_prefix) + "_" + str.__str__(suffix)


def _profile_keyed_items(value: object, *, reason_prefix: str) -> tuple[tuple[str, int, object, str], ...] | None:
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    keyed: list[tuple[str, int, object, str]] = []
    for index, (key, item) in enumerate(items):
        key_text, key_reason = no_hook_json_key(key, index, prefix=_profile_reason(reason_prefix, "key"))
        keyed.append((key_text, index, item, key_reason))
    return tuple(sorted(keyed, key=lambda row: (row[0], row[1])))


def _profile_sorted_values(value: set[object] | frozenset[object]) -> tuple[object, ...]:
    rows = list(value)
    rows.sort(key=_profile_state_sort_key)
    return tuple(rows)


def _freeze_profile_mapping(
    keyed: tuple[tuple[str, int, object, str], ...],
) -> Mapping[str, object]:
    out: dict[str, object] = {}
    for key_text, index, item, key_reason in keyed:
        output_key = (
            no_hook_duplicate_key(key_text, index, rejection="profile_duplicate_key_rejected")
            if key_text in out
            else key_text
        )
        if key_reason:
            out[output_key] = _profile_unavailable(item, key_reason)
        else:
            out[output_key] = _freeze_profile_value(item)
    return MappingProxyType(out)


def _freeze_profile_nonmapping(value: object) -> object:
    if value is not None and isinstance(value, Mapping):
        frozen: object = _profile_unavailable(value, "non_materializable_profile_mapping")
    elif type(value) in (set, frozenset):
        frozen = tuple(
            _freeze_profile_value(item) for item in _profile_sorted_values(value)
        )
    elif type(value) in (list, tuple):
        frozen = tuple(_freeze_profile_value(item) for item in value)
    elif type(value) in (str, bytes, bytearray, bool, int, float) or value is None:
        frozen = no_hook_materialize(value, reason_prefix="profile_value")
    else:
        frozen = _profile_unavailable(value, "non_materializable_profile_value")
    return frozen


def _freeze_profile_value(value: object) -> object:
    keyed = _profile_keyed_items(value, reason_prefix="profile")
    if keyed is not None:
        return _freeze_profile_mapping(keyed)
    return _freeze_profile_nonmapping(value)


def _detach_profile_value(value: object) -> object:
    keyed = _profile_keyed_items(value, reason_prefix="profile")
    if keyed is not None:
        out: dict[str, object] = {}
        for key_text, index, item, key_reason in keyed:
            output_key = (
                no_hook_duplicate_key(key_text, index, rejection="profile_duplicate_key_rejected")
                if key_text in out
                else key_text
            )
            if key_reason:
                out[output_key] = no_hook_failure(key_reason, item)
            else:
                out[output_key] = _detach_profile_value(item)
        return out
    if type(value) is tuple:
        return [_detach_profile_value(item) for item in value]
    if type(value) is list:
        return [_detach_profile_value(item) for item in value]
    return no_hook_materialize(value, reason_prefix="profile_value")


@dataclass
class ProfileScoringState:
    _lock: RLock = field(default_factory=RLock)
    _snapshot: Mapping[str, object] = field(default_factory=dict)
    _frozen: bool = False

    def freeze(self, snapshot: dict[str, object]) -> dict[str, object]:
        with self._lock:
            self._snapshot = _freeze_profile_value(snapshot if snapshot is not None else {})
            self._frozen = True
            return _detach_profile_value(self._snapshot)

    def clear(self) -> None:
        with self._lock:
            self._snapshot = {}
            self._frozen = False

    def is_frozen(self) -> bool:
        with self._lock:
            return self._frozen

    def get_profile(self, engine: str) -> object:
        with self._lock:
            engine_key, engine_reason = no_hook_json_key(engine if engine is not None else 'other', 0, prefix='profile_engine')
            value = None if engine_reason else self._snapshot.get(engine_key)
            return _detach_profile_value(value)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return _detach_profile_value(self._snapshot)


_PROFILE_SCORING_STATE = ProfileScoringState()


def profile_scoring_state() -> ProfileScoringState:
    return _PROFILE_SCORING_STATE


__all__ = ('ProfileScoringState', 'profile_scoring_state')
