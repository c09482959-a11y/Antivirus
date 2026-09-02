"""Immutable runtime transition core for replay-sensitive orchestration state.

Stage108 introduces a small deterministic reducer used by tests and new
provenance/recovery code to make state transitions auditable without mutating
caller-owned dictionaries.  It is deliberately standalone so older modules can
adopt it incrementally without changing detection/scoring behavior.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping
import hashlib
import json
import math
import threading

from Virus_Scan.contracts.no_hook_materialization import (
    exact_int_or_none,
    materialize_json_no_hook,
    no_hook_duplicate_key,
    no_hook_failure,
    no_hook_json_key,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    no_hook_text,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.provenance import append_provenance_event, stable_digest


def _frozen_failure(reason: str, value: object) -> Mapping[str, object]:
    return MappingProxyType(no_hook_failure(reason, value))


def _runtime_reason(prefix: str, suffix: str) -> str:
    prefix_text = str.__str__(prefix) if type(prefix) is str else "runtime"
    suffix_text = str.__str__(suffix) if type(suffix) is str else "runtime_reason"
    return prefix_text + "_" + suffix_text


def _runtime_owner_mismatch_message(left: str, right: str) -> str:
    left_text = str.__repr__(left) if type(left) is str else "'runtime_owner_rejected'"
    right_text = str.__repr__(right) if type(right) is str else "'runtime_owner_rejected'"
    return "runtime state owner mismatch: " + left_text + " cannot mutate " + right_text


def _runtime_action_rejected_message(action: str) -> str:
    action_text = str.__str__(action) if type(action) is str else "runtime_action_rejected"
    return "unsupported runtime transition action: " + action_text


def _runtime_text(value: object, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_runtime_text",
        unsupported_reason="unsafe_runtime_text_rejected",
    )
    if reason or text == "":
        return default
    return text


def _runtime_int(value: object, default: int) -> int:
    metric = exact_int_or_none(value)
    if metric is None:
        return default
    return metric


def _freeze_mapping_items(items: tuple[tuple[object, object], ...], *, reason_prefix: str, depth: int, max_depth: int, max_items: int) -> Mapping[str, object]:
    if len(items) > max_items:
        return _frozen_failure(_runtime_reason(reason_prefix, "mapping_size_limit_exceeded"), items)
    keyed: list[tuple[str, int, object, str]] = []
    for index, (key, item) in enumerate(items):
        key_text, key_reason = no_hook_json_key(key, index, prefix=_runtime_reason(reason_prefix, "key"))
        keyed.append((key_text, index, item, key_reason))
    out: dict[str, object] = {}
    for key_text, index, item, key_reason in sorted(keyed, key=lambda row: (row[0], row[1])):
        output_key = (
            no_hook_duplicate_key(key_text, index, rejection="runtime_duplicate_key_rejected")
            if key_text in out
            else key_text
        )
        if key_reason:
            out[output_key] = _frozen_failure(key_reason, item)
        else:
            out[output_key] = freeze_runtime_value(item, _depth=depth + 1, _max_depth=max_depth, _max_items=max_items)
    return MappingProxyType(out)


def freeze_runtime_value(value: object, *, _depth: int = 0, _max_depth: int = 12, _max_items: int = 512) -> object:
    """Return an immutable runtime snapshot without invoking caller-owned hooks.

    Only exact builtin containers and mapping proxies backed by exact dicts are
    traversed.  Unknown mappings, iterables, dataclasses, and scalar-like
    objects are converted into explicit unavailable evidence instead of being
    probed, stringified, or retained by reference.
    """
    if _depth > _max_depth:
        return _frozen_failure("runtime_depth_limit_exceeded", value)
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        if math.isfinite(value):
            return value
        return _frozen_failure("non_finite_runtime_number", value)
    if isinstance(value, str):
        return str.__str__(value)
    if type(value) is bytes:
        return materialize_json_no_hook(value, context="runtime_bytes", max_depth=1, max_items=_max_items)
    if type(value) is bytearray:
        return materialize_json_no_hook(value, context="runtime_bytearray", max_depth=1, max_items=_max_items)
    items = no_hook_mapping_items(value)
    if items is not None:
        return _freeze_mapping_items(items, reason_prefix="runtime", depth=_depth, max_depth=_max_depth, max_items=_max_items)
    if type(value) is tuple or type(value) is list:
        if len(value) > _max_items:
            return _frozen_failure("runtime_sequence_size_limit_exceeded", value)
        return tuple(freeze_runtime_value(item, _depth=_depth + 1, _max_depth=_max_depth, _max_items=_max_items) for item in value)
    if type(value) is frozenset or type(value) is set:
        if len(value) > _max_items:
            return _frozen_failure("runtime_set_size_limit_exceeded", value)
        frozen = tuple(freeze_runtime_value(item, _depth=_depth + 1, _max_depth=_max_depth, _max_items=_max_items) for item in value)
        return tuple(sorted(frozen, key=no_hook_json_sort_key))
    return _frozen_failure("non_materializable_runtime_value", value)


def materialize_runtime_value(value: object) -> object:
    return materialize_json_no_hook(value, context="runtime")


def _json_safe(value: object) -> object:
    return materialize_runtime_value(value)


@dataclass(frozen=True)
class RuntimeTransition:
    owner: str
    action: str
    key: str
    value: object = None
    parent: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if type(self) is not RuntimeTransition:
            raise TypeError("runtime transition owner rejected")
        object.__setattr__(self, "owner", _runtime_text(self.owner, "runtime"))
        object.__setattr__(self, "action", _runtime_text(self.action, "set"))
        object.__setattr__(self, "key", _runtime_text(self.key, ""))
        object.__setattr__(self, "value", freeze_runtime_value(self.value))
        object.__setattr__(self, "parent", _runtime_text(self.parent, ""))
        object.__setattr__(self, "reason", _runtime_text(self.reason, ""))

    def canonical(self) -> dict[str, object]:
        return {
            "owner": _runtime_text(self.owner, "runtime"),
            "action": _runtime_text(self.action, "set"),
            "key": _runtime_text(self.key, ""),
            "value": _json_safe(self.value),
            "parent": _runtime_text(self.parent, ""),
            "reason": _runtime_text(self.reason, ""),
        }

    @property
    def fingerprint(self) -> str:
        return stable_digest("runtime_transition", self.canonical())


@dataclass(frozen=True)
class ImmutableRuntimeState:
    version: int = 0
    values: Mapping[str, object] = field(default_factory=dict)
    history: tuple[Mapping[str, object], ...] = ()
    digest: str = ""

    def __post_init__(self) -> None:
        if type(self) is not ImmutableRuntimeState:
            raise TypeError("immutable runtime state owner rejected")
        object.__setattr__(self, "values", freeze_runtime_value({} if self.values is None else self.values))
        source_history = () if self.history is None else self.history
        if type(source_history) is tuple or type(source_history) is list:
            history = tuple(freeze_runtime_value(item) for item in source_history)
        else:
            history = (_frozen_failure("non_materializable_runtime_history", source_history),)
        object.__setattr__(self, "history", history)
        object.__setattr__(self, "digest", _runtime_text(self.digest, ""))

    def snapshot(self) -> Mapping[str, object]:
        return self.values



def _immutable_state_from_frozen(
    *,
    version: int,
    values: dict[str, object],
    history: tuple[Mapping[str, object], ...],
    digest: str,
) -> ImmutableRuntimeState:
    """Build an internal state snapshot from already-frozen reducer values.

    Public ``ImmutableRuntimeState`` construction still validates and freezes
    caller-owned inputs.  ``RuntimeStateReducer.apply`` owns its local ``values``
    dictionary and ``history`` tuple, so re-running the full public constructor on
    every transition repeatedly walks historical events under the reducer lock.
    This constructor keeps the public immutability contract without quadratic
    refreezing in concurrent scheduler lifecycle paths.
    """
    state = object.__new__(ImmutableRuntimeState)
    object.__setattr__(state, "version", version)
    object.__setattr__(state, "values", MappingProxyType(values))
    object.__setattr__(state, "history", history)
    object.__setattr__(state, "digest", _runtime_text(digest, ""))
    return state

def _state_digest(
    version: int,
    values: Mapping[str, object],
    history: tuple[Mapping[str, object], ...],
    *,
    previous_digest: str = "",
) -> str:
    """Return a deterministic state digest without rematerializing full history.

    Runtime reducers can be driven by hundreds of worker-lifecycle transitions
    during full-suite validation.  Hashing the complete history after every
    transition is quadratic and keeps competing worker threads blocked on the
    reducer lock.  The digest still commits to the full transition chain by
    carrying the previous digest forward, while only materializing the current
    values and a bounded history tail for replay/debug context.
    """
    payload = {
        "version": version,
        "values": _json_safe(values),
        "history_count": len(history),
        "history_tail": materialize_runtime_value(tuple(history[-16:])),
        "previous_digest": _runtime_text(previous_digest, ""),
    }
    try:
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()[:32]
    except RECOVERABLE_RUNTIME_ERRORS:
        return stable_digest(payload)


class RuntimeStateReducer:
    """Thread-safe immutable state reducer with explicit mutation ownership."""

    def __init__(self, *, owner: str = "runtime", max_history: int = 1024) -> None:
        self.owner = _runtime_text(owner, "runtime")
        self.max_history = max(1, _runtime_int(max_history, 1024))
        self._lock = threading.RLock()
        self._state = ImmutableRuntimeState(digest=_state_digest(0, {}, ()))

    def current(self) -> ImmutableRuntimeState:
        with self._lock:
            return self._state

    def apply(self, transition: RuntimeTransition | Mapping[str, object]) -> ImmutableRuntimeState:
        if not isinstance(transition, RuntimeTransition):
            items = no_hook_mapping_items(transition)
            if items is None:
                transition = RuntimeTransition(owner=self.owner, action="set", key="", value=_frozen_failure("non_materializable_runtime_transition", transition))
            else:
                transition = RuntimeTransition(
                    **{
                        str.__str__(key): item
                        for key, item in items
                        if type(key) is str
                    }
                )
        if transition.owner != "" and _runtime_text(transition.owner) != self.owner:
            raise PermissionError(_runtime_owner_mismatch_message(transition.owner, self.owner))
        event = transition.canonical()
        event["fingerprint"] = transition.fingerprint
        with self._lock:
            values = dict(self._state.values)
            action = event["action"]
            key = event["key"]
            if action == "set":
                values[key] = event["value"]
            elif action == "delete":
                values.pop(key, None)
            elif action == "append":
                cur = values.get(key, [])
                if not isinstance(cur, list):
                    cur = [cur]
                values[key] = [*cur, event['value']]
            else:
                raise ValueError(_runtime_action_rejected_message(action))
            version = self._state.version + 1
            previous_digest = self._state.digest
            event["version"] = version
            frozen_event = freeze_runtime_value(event)
            history = ((*self._state.history, frozen_event))[-self.max_history:]
            digest = _state_digest(version, values, history, previous_digest=previous_digest)
            new_state = _immutable_state_from_frozen(
                version=version,
                values=values,
                history=history,
                digest=digest,
            )
            self._state = new_state
        append_provenance_event({"event_type": "runtime_transition", "owner": self.owner, "transition": event, "state_digest": new_state.digest})
        return new_state

    def canonical_history(self) -> list[dict[str, object]]:
        with self._lock:
            return [dict(materialize_runtime_value(e)) for e in self._state.history]


__all__ = ("ImmutableRuntimeState", "RuntimeStateReducer", "RuntimeTransition", "freeze_runtime_value", "materialize_runtime_value")
