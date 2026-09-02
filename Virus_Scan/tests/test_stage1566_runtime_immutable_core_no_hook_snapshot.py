from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from Virus_Scan.runtime.immutable_core import (
    ImmutableRuntimeState,
    RuntimeStateReducer,
    RuntimeTransition,
    freeze_runtime_value,
    materialize_runtime_value,
)


class HostileMapping(Mapping):
    def __iter__(self):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned __iter__ was invoked")

    def __len__(self):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned __len__ was invoked")

    def __getitem__(self, key):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned __getitem__ was invoked")

    def keys(self):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned keys was invoked")

    def items(self):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned items was invoked")

    def values(self):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned values was invoked")

    def get(self, key, default=None):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned get was invoked")


class HostileScalar:
    def __str__(self):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned __str__ was invoked")

    def __repr__(self):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned __repr__ was invoked")

    def __bool__(self):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned __bool__ was invoked")

    def __iter__(self):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned __iter__ was invoked")


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.str_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves unsafe hook use
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def __repr__(self):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned __repr__ was invoked")

    def __format__(self, format_spec):  # pragma: no cover - failure proves unsafe hook use
        raise AssertionError("caller-owned __format__ was invoked")


def test_runtime_freeze_rejects_unknown_mapping_without_mapping_hooks() -> None:
    frozen = freeze_runtime_value({"safe": HostileMapping()})
    materialized = materialize_runtime_value(frozen)

    assert materialized["safe"]["unavailable_reason"] == "non_materializable_runtime_value"
    assert materialized["safe"]["value_type"] == "HostileMapping"
    json.dumps(materialized, sort_keys=True)


def test_runtime_transition_rejects_unsupported_object_without_scalar_or_iter_hooks() -> None:
    transition = RuntimeTransition(owner="runtime", action="set", key="unsafe", value=HostileScalar())

    assert transition.canonical()["value"]["unavailable_reason"] == "non_materializable_runtime_value"
    assert transition.canonical()["value"]["value_type"] == "HostileScalar"
    json.dumps(transition.canonical(), sort_keys=True)


def test_runtime_state_history_rejects_hostile_history_object_without_iterating_it() -> None:
    state = ImmutableRuntimeState(values={"ok": 1}, history=HostileScalar())

    materialized_history = materialize_runtime_value(state.history)
    assert materialized_history[0]["unavailable_reason"] == "non_materializable_runtime_history"
    assert materialized_history[0]["value_type"] == "HostileScalar"


def test_runtime_snapshot_detaches_exact_builtin_containers_and_text_subclasses() -> None:
    text = HostileText("queued")
    source = {"job": {"tags": [text]}}

    state = ImmutableRuntimeState(values=source)
    source["job"]["tags"].append("mutated")

    assert state.values["job"]["tags"] == ("queued",)
    assert text.str_calls == 0
    assert materialize_runtime_value(state.values) == {"job": {"tags": ["queued"]}}


def test_stage1970_runtime_immutable_core_reasons_duplicates_and_reducer_errors_are_no_hook() -> None:
    duplicate_key = HostileText("duplicate")
    owner = HostileText("runtime")
    mismatched_owner = HostileText("other")
    bad_action = HostileText("unsupported")

    limited = freeze_runtime_value({"a": 1, "b": 2}, _max_items=1)
    duplicated = freeze_runtime_value({1: duplicate_key, "1": 2})
    reducer = RuntimeStateReducer(owner=owner)

    with pytest.raises(PermissionError, match="runtime state owner mismatch"):
        reducer.apply(RuntimeTransition(owner=mismatched_owner, action="set", key="unit", value=1))
    with pytest.raises(ValueError, match="unsupported runtime transition action"):
        reducer.apply(RuntimeTransition(owner=owner, action=bad_action, key="unit", value=1))

    assert limited["unavailable_reason"] == "runtime_mapping_size_limit_exceeded"
    assert duplicated == {"1": "duplicate", "1#1": 2}
    assert duplicate_key.str_calls == 0
    assert owner.str_calls == 0
    assert mismatched_owner.str_calls == 0
    assert bad_action.str_calls == 0
