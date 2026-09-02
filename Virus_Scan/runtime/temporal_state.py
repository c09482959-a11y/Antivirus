"""Canonical runtime owner for temporal v5 events and accumulator state."""
from __future__ import annotations

from collections import defaultdict, deque
import math
from threading import RLock
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.temporal_accumulator import (
    TemporalAccumulatorState,
    initial_temporal_accumulator_state,
)
from Virus_Scan.contracts.temporal_event import TemporalEvent
from Virus_Scan.contracts.temporal_learning import (
    TEMPORAL_RUNTIME_STATE_SCHEMA,
    TemporalLearningRequest,
)
from Virus_Scan.runtime.cache_state import runtime_cache_by_name

_MAX_HISTORY = 25
_MAX_KEYS = 4096
_HEX = frozenset("0123456789abcdef")
_NODE_FIELDS = frozenset({
    "history", "belief", "hidden_state", "last_snapshot",
    "last_learning_ordinal",
})


def temporal_state_node_key(node: object) -> str:
    if type(node) is str:
        text = str.strip(str.__str__(node))
        return text or "<unknown>"
    if node is None:
        return "<unknown>"
    return "<" + type(node).__name__ + ">"


def _default_state() -> dict[str, object]:
    initial = initial_temporal_accumulator_state()
    return {
        "history": deque(maxlen=_MAX_HISTORY),
        "belief": 0.0,
        "hidden_state": initial,
        "last_snapshot": None,
        "last_learning_ordinal": -1,
    }


def _valid_replay_key(value: object) -> str:
    if type(value) is not str:
        raise ValueError("temporal learning replay key invalid")
    key = str.__str__(value)
    if len(key) != 64 or any(char not in _HEX for char in key):
        raise ValueError("temporal learning replay key invalid")
    return key


def _probability(value: object) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        raise ValueError("temporal probability invalid")
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError("temporal probability invalid")
    return number


def _optional_finite(value: object) -> float | None:
    if value is None:
        return None
    if type(value) not in (int, float) or isinstance(value, bool):
        raise ValueError("temporal timestamp invalid")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("temporal timestamp invalid")
    return number


def _ordinal(value: object, *, allow_unset: bool = False) -> int:
    if type(value) is not int or isinstance(value, bool):
        raise ValueError("temporal learning ordinal invalid")
    if value < (-1 if allow_unset else 0):
        raise ValueError("temporal learning ordinal invalid")
    return value


def _freeze(value: object) -> object:
    if type(value) is dict:
        return MappingProxyType({
            key: _freeze(child) for key, child in sorted(value.items())
        })
    if type(value) is list:
        return tuple(_freeze(child) for child in value)
    if type(value) is tuple:
        return tuple(_freeze(child) for child in value)
    return value


def _state_belief(hidden: TemporalAccumulatorState) -> float:
    return _probability(hidden.posterior_belief * hidden.maturity)


class TemporalStateOwner:
    """Single mutation authority for canonical temporal runtime evidence."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._state: defaultdict[str, dict[str, object]] = defaultdict(
            _default_state
        )
        self._learning_keys: dict[str, int] = {}
        self._cache = runtime_cache_by_name("TEMPORAL_CACHE")

    @property
    def lock(self) -> RLock:
        return self._lock

    def has_node(self, node: object) -> bool:
        key = temporal_state_node_key(node)
        with self._lock:
            return key in self._state

    def history_snapshot(self, node: object) -> tuple[TemporalEvent, ...]:
        key = temporal_state_node_key(node)
        with self._lock:
            history = self._state.get(key, {}).get("history", ())
            if type(history) is not deque:
                return ()
            return tuple(
                event for event in history if type(event) is TemporalEvent
            )

    def state_snapshot(self, node: object) -> Mapping[str, object]:
        key = temporal_state_node_key(node)
        with self._lock:
            state = self._state.get(key)
            if type(state) is not dict:
                state = _default_state()
            history = state.get("history", ())
            events = tuple(history) if type(history) is deque else ()
            hidden = state.get("hidden_state")
            if type(hidden) is not TemporalAccumulatorState:
                hidden = initial_temporal_accumulator_state()
            hidden.validate()
            return MappingProxyType({
                "history": events,
                "belief": _probability(state.get("belief", 0.0)),
                "hidden_state": _freeze(hidden.to_record()),
                "last_snapshot": _optional_finite(state.get("last_snapshot")),
                "last_learning_ordinal": _ordinal(
                    state.get("last_learning_ordinal", -1), allow_unset=True,
                ),
            })

    def commit_request(self, request: TemporalLearningRequest) -> bool:
        if type(request) is not TemporalLearningRequest:
            raise TypeError("temporal learning request required")
        request.validate()
        replay_key = _valid_replay_key(request.replay_key)
        with self._lock:
            if replay_key in self._learning_keys:
                return False
            state = self._state[temporal_state_node_key(request.node_id)]
            history = state["history"]
            assert type(history) is deque
            history.extend(request.events)
            hidden = request.accumulator_state
            state["hidden_state"] = hidden
            state["belief"] = _state_belief(hidden)
            state["last_snapshot"] = hidden.last_evidence_timestamp
            state["last_learning_ordinal"] = request.decision_ordinal
            self._learning_keys[replay_key] = request.decision_ordinal
            self._prune_learning_keys()
            return True

    def _prune_learning_keys(self) -> None:
        if len(self._learning_keys) <= _MAX_KEYS:
            return
        retained = {
            key for _ordinal_value, key in sorted(
                (ordinal, key) for key, ordinal in self._learning_keys.items()
            )[-_MAX_KEYS:]
        }
        for key in tuple(self._learning_keys):
            if key not in retained:
                self._learning_keys.pop(key, None)

    def learning_keys_snapshot(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                key for _ordinal_value, key in sorted(
                    (ordinal, key) for key, ordinal in self._learning_keys.items()
                )
            )

    def to_record(self) -> dict[str, object]:
        with self._lock:
            nodes: dict[str, object] = {}
            for node in sorted(self._state):
                state = self._state[node]
                history = state.get("history", ())
                events = list(history) if type(history) is deque else []
                hidden = state.get("hidden_state")
                if type(hidden) is not TemporalAccumulatorState:
                    hidden = initial_temporal_accumulator_state()
                nodes[node] = {
                    "history": [event.to_record() for event in events],
                    "belief": _probability(state.get("belief", 0.0)),
                    "hidden_state": hidden.to_record(),
                    "last_snapshot": _optional_finite(
                        state.get("last_snapshot")
                    ),
                    "last_learning_ordinal": _ordinal(
                        state.get("last_learning_ordinal", -1), allow_unset=True,
                    ),
                }
            return {
                "schema_version": TEMPORAL_RUNTIME_STATE_SCHEMA,
                "nodes": nodes,
                "applied_learning_keys": [
                    {"replay_key": key, "decision_ordinal": ordinal}
                    for ordinal, key in sorted(
                        (ordinal, key)
                        for key, ordinal in self._learning_keys.items()
                    )[-_MAX_KEYS:]
                ],
            }

    def load_record(self, value: object) -> dict[str, object]:
        if type(value) is not dict:
            return {"loaded": False, "reason": "temporal_state_non_mapping"}
        if dict.get(value, "schema_version") != TEMPORAL_RUNTIME_STATE_SCHEMA:
            return {"loaded": False, "reason": "temporal_state_schema_invalid"}
        if frozenset(value) != frozenset({
            "schema_version", "nodes", "applied_learning_keys",
        }):
            return {"loaded": False, "reason": "temporal_state_fields_invalid"}
        raw_nodes = dict.get(value, "nodes")
        raw_keys = dict.get(value, "applied_learning_keys")
        if type(raw_nodes) is not dict or type(raw_keys) is not list:
            return {"loaded": False, "reason": "temporal_state_sections_invalid"}
        prepared: defaultdict[str, dict[str, object]] = defaultdict(
            _default_state
        )
        try:
            for node, raw_state in sorted(raw_nodes.items()):
                if type(node) is not str or node == "" or type(raw_state) is not dict:
                    raise ValueError("temporal_node_state_invalid")
                if frozenset(raw_state) != _NODE_FIELDS:
                    raise ValueError("temporal_node_state_fields_invalid")
                raw_history = raw_state.get("history")
                if type(raw_history) is not list or len(raw_history) > _MAX_HISTORY:
                    raise ValueError("temporal_history_invalid")
                history: deque[TemporalEvent] = deque(maxlen=_MAX_HISTORY)
                for raw_event in raw_history:
                    history.append(TemporalEvent.from_record(raw_event))
                hidden = TemporalAccumulatorState.from_record(
                    raw_state.get("hidden_state")
                )
                belief = _probability(raw_state.get("belief"))
                if belief != _state_belief(hidden):
                    raise ValueError("temporal_belief_identity_mismatch")
                last_snapshot = _optional_finite(raw_state.get("last_snapshot"))
                if last_snapshot != hidden.last_evidence_timestamp:
                    raise ValueError("temporal_snapshot_identity_mismatch")
                prepared[node] = {
                    "history": history,
                    "belief": belief,
                    "hidden_state": hidden,
                    "last_snapshot": last_snapshot,
                    "last_learning_ordinal": _ordinal(
                        raw_state.get("last_learning_ordinal"), allow_unset=True,
                    ),
                }
            if len(raw_keys) > _MAX_KEYS:
                raise ValueError("temporal_learning_keys_unbounded")
            prepared_keys: dict[str, int] = {}
            for row in raw_keys:
                if type(row) is not dict or frozenset(row) != frozenset({
                    "replay_key", "decision_ordinal",
                }):
                    raise ValueError("temporal_learning_key_record_invalid")
                key = _valid_replay_key(row.get("replay_key"))
                ordinal = _ordinal(row.get("decision_ordinal"))
                if key in prepared_keys:
                    raise ValueError("temporal_learning_replay_key_duplicate")
                prepared_keys[key] = ordinal
        except (ValueError, TypeError) as exc:
            return {"loaded": False, "reason": str(exc).replace(" ", "_")}
        with self._lock:
            self._state.clear()
            self._state.update(prepared)
            self._learning_keys.clear()
            self._learning_keys.update(prepared_keys)
            self._cache.clear()
        return {
            "loaded": True,
            "reason": None,
            "nodes_loaded": len(prepared),
            "learning_keys_loaded": len(prepared_keys),
            "schema_version": TEMPORAL_RUNTIME_STATE_SCHEMA,
        }

    def invalidate_cache(self, *nodes: object) -> None:
        with self._lock:
            for node in nodes:
                self._cache.pop(
                    "temporal:" + temporal_state_node_key(node), None
                )

    def prune_for_retention(
        self, *, max_nodes: int, max_history_per_node: int,
    ) -> None:
        for value, name in (
            (max_nodes, "temporal max nodes"),
            (max_history_per_node, "temporal max history"),
        ):
            if type(value) is not int or isinstance(value, bool) or value < 0:
                raise ValueError(name + " invalid")
        with self._lock:
            for state in self._state.values():
                history = state.get("history", ())
                values = list(history) if type(history) is deque else []
                state["history"] = deque(
                    values[-max_history_per_node:] if max_history_per_node else (),
                    maxlen=max_history_per_node or _MAX_HISTORY,
                )
            if len(self._state) > max_nodes:
                def rank(
                    item: tuple[str, dict[str, object]],
                ) -> tuple[int, float, int, str]:
                    key, state = item
                    try:
                        belief = _probability(state.get("belief", 0.0))
                        ordinal = _ordinal(
                            state.get("last_learning_ordinal", -1),
                            allow_unset=True,
                        )
                    except (TypeError, ValueError):
                        return (1, 0.0, 0, key)
                    return (0, -belief, -ordinal, key)
                retained = dict(
                    sorted(self._state.items(), key=rank)[:max_nodes]
                ) if max_nodes else {}
                self._state.clear()
                self._state.update(retained)


_TEMPORAL_STATE = TemporalStateOwner()


def temporal_owner() -> TemporalStateOwner:
    return _TEMPORAL_STATE


def temporal_has_node(node: object) -> bool:
    return _TEMPORAL_STATE.has_node(node)


def temporal_history_snapshot(node: object) -> tuple[TemporalEvent, ...]:
    return _TEMPORAL_STATE.history_snapshot(node)


def temporal_node_state_snapshot(node: object) -> Mapping[str, object]:
    return _TEMPORAL_STATE.state_snapshot(node)


def commit_temporal_learning_request(request: TemporalLearningRequest) -> bool:
    return _TEMPORAL_STATE.commit_request(request)


def temporal_learning_keys_snapshot() -> tuple[str, ...]:
    return _TEMPORAL_STATE.learning_keys_snapshot()


def temporal_runtime_state_to_json() -> dict[str, object]:
    return _TEMPORAL_STATE.to_record()


def load_temporal_runtime_state(value: object) -> dict[str, object]:
    return _TEMPORAL_STATE.load_record(value)


def invalidate_temporal_cache(*nodes: object) -> None:
    _TEMPORAL_STATE.invalidate_cache(*nodes)


def prune_temporal_state_for_retention(
    *, max_nodes: int, max_history_per_node: int,
) -> None:
    _TEMPORAL_STATE.prune_for_retention(
        max_nodes=max_nodes,
        max_history_per_node=max_history_per_node,
    )


__all__ = (
    "TEMPORAL_RUNTIME_STATE_SCHEMA",
    "TemporalStateOwner",
    "commit_temporal_learning_request",
    "invalidate_temporal_cache",
    "load_temporal_runtime_state",
    "prune_temporal_state_for_retention",
    "temporal_has_node",
    "temporal_history_snapshot",
    "temporal_learning_keys_snapshot",
    "temporal_node_state_snapshot",
    "temporal_owner",
    "temporal_runtime_state_to_json",
    "temporal_state_node_key",
)
