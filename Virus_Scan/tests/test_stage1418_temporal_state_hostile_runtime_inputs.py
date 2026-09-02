from __future__ import annotations

from collections.abc import Mapping

import pytest

from Virus_Scan.models.temporal.event_materialization import materialize_temporal_events
from Virus_Scan.runtime.temporal_state import (
    commit_temporal_learning_request,
    prune_temporal_state_for_retention,
    temporal_history_snapshot,
    temporal_state_node_key,
)


class HostileSequence:
    touched = 0
    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("truthiness unavailable")
    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iteration unavailable")


class HostileText:
    touched = 0
    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("truthiness unavailable")
    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("text unavailable")


class HostileInt:
    touched = 0
    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("int unavailable")


class HostileMapping(Mapping):
    touched = 0
    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("mapping iteration unavailable")
    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("mapping len unavailable")
    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("mapping item unavailable")
    def items(self):
        type(self).touched += 1
        raise RuntimeError("mapping items unavailable")


def test_stage1418_event_materializer_rejects_hostile_inputs_without_hooks():
    HostileSequence.touched = HostileText.touched = 0
    events, validations = materialize_temporal_events(
        ordered_events=HostileSequence(), behavior_flow=HostileSequence(),
        observation_id="stage1418", previous_stage=HostileText(),
        current_stage=HostileText(),
    )
    assert events == ()
    assert len(validations) == 1
    assert validations[0].status == "unavailable"
    assert validations[0].reasons == ("temporal_ordered_events_unavailable",)
    assert HostileSequence.touched == 0
    assert HostileText.touched == 0


def test_stage1418_runtime_commit_rejects_non_request_without_mapping_hooks():
    HostileMapping.touched = 0
    with pytest.raises(TypeError, match="temporal learning request required"):
        commit_temporal_learning_request(HostileMapping())
    assert HostileMapping.touched == 0
    assert temporal_state_node_key(HostileText()) == "<HostileText>"
    assert temporal_history_snapshot(HostileText()) == ()
    assert HostileText.touched == 0


def test_stage1418_temporal_retention_strictly_rejects_hostile_limits():
    HostileInt.touched = 0
    with pytest.raises(ValueError, match="temporal max nodes invalid"):
        prune_temporal_state_for_retention(
            max_nodes=HostileInt(), max_history_per_node=HostileInt(),
        )
    assert HostileInt.touched == 0
