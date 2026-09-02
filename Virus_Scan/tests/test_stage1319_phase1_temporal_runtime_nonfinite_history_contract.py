from __future__ import annotations

from copy import deepcopy
import json
import math

from Virus_Scan.contracts.temporal_accumulator import TemporalAccumulatorState
from Virus_Scan.runtime.temporal_state import (
    TemporalStateOwner,
    load_temporal_runtime_state,
    temporal_history_snapshot,
    temporal_runtime_state_to_json,
)
from Virus_Scan.models import temporal
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.tests.support.temporal_v5 import temporal_v5_event, temporal_v5_request


def _state(*, belief: float, support: int) -> TemporalAccumulatorState:
    return TemporalAccumulatorState(
        prior_belief=belief,
        current_observation=belief,
        observation_confidence=1.0,
        elapsed_evidence_time=0.0,
        posterior_belief=belief,
        support=support,
        maturity=1.0,
        last_evidence_timestamp=None,
        unavailable_reason=None,
    )


def test_stage1319_temporal_runtime_loader_rejects_nonfinite_v5_event_without_mutating_live_state():
    node = "stage1319-temporal-corrupt-history"
    temporal.update_temporal(
        node, "runtime", ["download", "exec"],
        ordered_events=[
            {"tag": "download", "timestamp": 125.0, "stage": "runtime"},
            {"tag": "exec", "timestamp": 126.0, "stage": "runtime"},
        ],
        learning_decision=accepted_learning_decision(
            target_names=("temporal",), observation_id="stage1319-valid-live",
        ),
    )
    before = temporal_history_snapshot(node)
    record = deepcopy(temporal_runtime_state_to_json())
    record["nodes"][node]["history"][0]["timestamp_value"] = math.inf

    result = load_temporal_runtime_state(record)

    assert result["loaded"] is False
    assert "timestamp" in result["reason"]
    assert temporal_history_snapshot(node) == before
    json.dumps(temporal_runtime_state_to_json(), allow_nan=False)


def test_stage1319_temporal_retention_uses_only_valid_canonical_v5_state():
    owner = TemporalStateOwner()
    low_event = temporal_v5_event(
        event_id="stage1319-low-event", source_evidence_id="stage1319-low-root",
        behavior_id="download", stage="runtime", source_ordinal=0,
    )
    high_event = temporal_v5_event(
        event_id="stage1319-high-event", source_evidence_id="stage1319-high-root",
        behavior_id="exec", stage="runtime", source_ordinal=0,
    )
    assert owner.commit_request(temporal_v5_request(
        node_id="stage1319-low", events=(low_event,),
        accumulator_state=_state(belief=0.25, support=2), decision_ordinal=1,
    )) is True
    assert owner.commit_request(temporal_v5_request(
        node_id="stage1319-high", events=(high_event,),
        accumulator_state=_state(belief=0.75, support=4), decision_ordinal=2,
    )) is True

    corrupted = owner.to_record()
    corrupted["nodes"]["stage1319-high"]["belief"] = math.inf
    assert owner.load_record(corrupted)["loaded"] is False

    owner.prune_for_retention(max_nodes=1, max_history_per_node=25)
    record = owner.to_record()
    assert tuple(record["nodes"]) == ("stage1319-high",)
    json.dumps(record, allow_nan=False)
