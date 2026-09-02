import math
from types import MappingProxyType

import pytest

from Virus_Scan.contracts.temporal_accumulator import TemporalAccumulatorState
from Virus_Scan.runtime.temporal_state import (
    commit_temporal_learning_request,
    temporal_node_state_snapshot,
)
from Virus_Scan.tests.support.temporal_v5 import (
    temporal_v5_event,
    temporal_v5_request,
)


def _contains_non_finite(value):
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, (dict, MappingProxyType)):
        return any(_contains_non_finite(item) for item in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_non_finite(item) for item in value)
    return False


def test_stage1311_temporal_commit_rejects_nonfinite_accumulator_state():
    node = "stage1311-temporal-nonfinite-state"
    event = temporal_v5_event(
        event_id="stage1311:event:0", source_evidence_id="stage1311:source:0",
        behavior_id="download", stage="runtime", source_ordinal=0,
    )
    invalid = TemporalAccumulatorState(
        prior_belief=0.0, current_observation=0.0,
        observation_confidence=0.0, elapsed_evidence_time=0.0,
        posterior_belief=math.inf, support=1, maturity=0.5,
        last_evidence_timestamp=None, unavailable_reason=None,
    )

    with pytest.raises(ValueError, match="posterior belief"):
        temporal_v5_request(
            node_id=node, events=(event,), accumulator_state=invalid,
        )

    snapshot = temporal_node_state_snapshot(node)
    assert snapshot["belief"] == 0.0
    assert snapshot["last_snapshot"] is None
    assert snapshot["hidden_state"]["posterior_belief"] == 0.0
    assert not _contains_non_finite(snapshot)


def test_stage1311_temporal_v5_snapshot_is_deeply_immutable_and_detached():
    node = "stage1311-temporal-detached-state"
    event_record = temporal_v5_event(
        event_id="stage1311:event:1", source_evidence_id="stage1311:source:1",
        behavior_id="process_create", stage="runtime", source_ordinal=0,
        timestamp_value=123.0, timestamp_kind="observed",
        clock_domain="scan_evidence", ordering_confidence=1.0,
    ).to_record()
    event = temporal_v5_event(
        event_id=event_record["event_id"],
        source_evidence_id=event_record["source_evidence_id"],
        behavior_id=event_record["behavior_id"], stage=event_record["stage"],
        source_ordinal=event_record["source_ordinal"],
        timestamp_value=event_record["timestamp_value"],
        timestamp_kind=event_record["timestamp_kind"],
        clock_domain=event_record["clock_domain"],
        ordering_confidence=event_record["ordering_confidence"],
    )
    state = TemporalAccumulatorState(
        prior_belief=0.2, current_observation=0.8,
        observation_confidence=0.75, elapsed_evidence_time=1.0,
        posterior_belief=0.65, support=4, maturity=1.0,
        last_evidence_timestamp=123.0, unavailable_reason=None,
    )
    request = temporal_v5_request(
        node_id=node, events=(event,), accumulator_state=state,
    )
    assert commit_temporal_learning_request(request) is True
    snapshot = temporal_node_state_snapshot(node)

    event_record["behavior_id"] = "mutated"
    assert snapshot["history"][0].behavior_id == "process_create"
    assert snapshot["hidden_state"]["posterior_belief"] == 0.65
    with pytest.raises(TypeError):
        snapshot["hidden_state"]["posterior_belief"] = 0.99
    with pytest.raises(TypeError):
        snapshot["extra"] = "mutated"
