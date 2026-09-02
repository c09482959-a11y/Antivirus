from __future__ import annotations

from copy import deepcopy
import inspect
import math

from Virus_Scan.models import temporal
from Virus_Scan.runtime.temporal_state import (
    load_temporal_runtime_state,
    temporal_history_snapshot,
    temporal_runtime_state_to_json,
)
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
import Virus_Scan.runtime.temporal_state as temporal_state_module


def _decision(name: str):
    return accepted_learning_decision(
        target_names=("temporal",), observation_id=name,
    )


def _semantic_history(node: str) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            event.stage, event.behavior_id, event.timestamp_kind,
            event.timestamp_value, event.clock_domain,
            event.ordering_confidence, event.source_ordinal,
        )
        for event in temporal_history_snapshot(node)
    )


def test_stage1342_update_temporal_uses_order_only_evidence_not_wall_clock_or_synthetic_ticks():
    node = "stage1342-temporal-order-only"
    temporal.update_temporal(
        node, "asset", ["download", "exec"],
        learning_decision=_decision("stage1342-order-1"),
    )
    temporal.update_temporal(
        node, "runtime", ["network", "persistence"], previous_stage="asset",
        learning_decision=_decision("stage1342-order-2"),
    )

    history = temporal_history_snapshot(node)

    assert tuple(event.behavior_id for event in history) == (
        "download", "exec", "network", "persistence",
    )
    assert all(event.timestamp_kind == "ordinal_only" for event in history)
    assert all(event.timestamp_value is None for event in history)
    assert all(event.clock_domain == "ordinal" for event in history)


def test_stage1342_identical_temporal_learning_sequences_materialize_identical_semantics():
    first_node = "stage1342-temporal-repeat-a"
    second_node = "stage1342-temporal-repeat-b"
    sequence = (
        ("asset", ["download", "exec"]),
        ("runtime", ["network", "persistence"]),
        ("final", ["archive", "exec"]),
    )
    previous = "unknown"
    for ordinal, (stage, tags) in enumerate(sequence):
        temporal.update_temporal(
            first_node, stage, tags, previous_stage=previous,
            learning_decision=_decision(f"stage1342-first-{ordinal}"),
        )
        previous = stage
    previous = "unknown"
    for ordinal, (stage, tags) in enumerate(sequence):
        temporal.update_temporal(
            second_node, stage, tags, previous_stage=previous,
            learning_decision=_decision(f"stage1342-second-{ordinal}"),
        )
        previous = stage

    assert _semantic_history(first_node) == _semantic_history(second_node)


def test_stage1342_nonfinite_persisted_timestamp_is_rejected_without_state_replacement():
    node = "stage1342-temporal-corrupt-last"
    temporal.update_temporal(
        node, "runtime", ["network"],
        ordered_events=[{"tag": "network", "timestamp": 1.0, "stage": "runtime"}],
        learning_decision=_decision("stage1342-valid-state"),
    )
    before = temporal_history_snapshot(node)
    record = deepcopy(temporal_runtime_state_to_json())
    record["nodes"][node]["history"][0]["timestamp_value"] = math.inf

    result = load_temporal_runtime_state(record)

    assert result["loaded"] is False
    assert temporal_history_snapshot(node) == before


def test_stage1342_temporal_runtime_state_source_has_no_live_clock_or_legacy_tick_owner():
    source = inspect.getsource(temporal_state_module)

    assert "from time import time" not in source
    assert "time.time" not in source
    assert "_next_observation_timestamp" not in source
    assert "temporal_runtime_state_v5" not in source or "TEMPORAL_RUNTIME_STATE_SCHEMA" in source
