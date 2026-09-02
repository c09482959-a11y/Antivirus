"""Stage 1516 Phase 1 runtime model/temporal text-boundary regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.runtime_model_state import current_runtime_model_record

from collections import Counter, defaultdict, deque

from Virus_Scan.models.temporal.event_materialization import materialize_temporal_events
from Virus_Scan.runtime import model_state, temporal_state
from Virus_Scan.tests.support.temporal_v5 import temporal_v5_request


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.bool_calls = 0
        obj.strip_calls = 0
        return obj

    def __str__(self):
        return self

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves raw caller strip was used
        self.strip_calls += 1
        raise AssertionError("caller-owned strip was invoked")

    def __bool__(self):  # pragma: no cover - failure proves truthiness regression
        self.bool_calls += 1
        raise AssertionError("caller-owned text truthiness was probed")


def _configure_fresh_runtime_model_state():
    transition_counts = defaultdict(Counter)
    global_tag_baseline = defaultdict(int)
    global_tag_pair_baseline = defaultdict(int)
    filetype_baseline = defaultdict(Counter)
    model_state.configure_runtime_model_state(
        transition_counts=transition_counts,
        global_tag_baseline=global_tag_baseline,
        global_tag_pair_baseline=global_tag_pair_baseline,
        filetype_baseline=filetype_baseline,
    )
    return transition_counts, global_tag_baseline, global_tag_pair_baseline, filetype_baseline


def test_stage1516_runtime_model_load_detaches_hostile_transition_and_pair_text():
    _configure_fresh_runtime_model_state()
    stage = HostileText(" stage_a ")
    event = HostileText(" event_a ")
    target = HostileText(" target_a ")
    pair_a = HostileText(" alpha ")
    pair_b = HostileText(" beta ")

    result = model_state.load_runtime_model_baselines(current_runtime_model_record({
        "transition_counts": (
            {
                "type": "markov_event_v2",
                "context": "global:trusted_benign",
                "previous_stage": stage,
                "source_event": event,
                "target": target,
                "count": 2,
            },
            {
                "type": "markov_stage_v2",
                "context": "global:trusted_benign",
                "previous_stage": stage,
                "flow_class": event,
                "target": target,
                "count": 3,
            },
        ),
        "global_tag_pair_baseline": ({"a": pair_a, "b": pair_b, "count": 4},),
    }))

    assert result["loaded"] is False
    assert result["reason"] == "runtime_model_snapshot_value_invalid"
    snapshot = model_state.runtime_model_snapshot(
        markov_key_to_json=model_state.runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )
    assert snapshot["transition_counts"] == []
    assert snapshot["global_tag_pair_baseline"] == []
    for value in (stage, event, target, pair_a, pair_b):
        assert value.strip_calls == 0
        assert value.bool_calls == 0


def test_stage1516_runtime_model_update_filetype_and_retention_detach_hostile_text():
    transition_counts, global_tag_baseline, global_tag_pair_baseline, filetype_baseline = _configure_fresh_runtime_model_state()
    ext = HostileText(" .rpa ")
    tag = HostileText(" archive_tag ")
    stage = HostileText(" stage_b ")
    model_state.update_filetype_baseline(ext, (tag,), mark_dirty=lambda: None)
    model_state.set_global_tag_count(tag, 7)
    transition_counts[(
        "markov_event_v2",
        ("global:trusted_benign", stage, tag),
    )] = Counter({stage: 5})
    global_tag_pair_baseline[(tag, stage)] = 3

    model_state.prune_runtime_model_mappings_for_retention(
        max_transition_keys=10,
        max_transition_next_keys=10,
        max_tag_counter_keys=10,
        max_pair_counter_keys=10,
        max_filetype_baselines=10,
    )

    snapshot = model_state.runtime_model_snapshot(
        markov_key_to_json=model_state.runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )
    assert snapshot["filetype_baseline"] == {".rpa": {"archive_tag": 1}}
    assert snapshot["global_tag_baseline"] == {"archive_tag": 7}
    assert snapshot["global_tag_pair_baseline"] == [{"a": "archive_tag", "b": "stage_b", "count": 3}]
    assert snapshot["transition_counts"] == [
        {
            "type": "markov_event_v2",
            "context": "global:trusted_benign",
            "previous_stage": "stage_b",
            "source_event": "archive_tag",
            "target": "stage_b",
            "count": 5,
        }
    ]
    for value in (ext, tag, stage):
        assert value.strip_calls == 0
        assert value.bool_calls == 0


def test_stage1516_temporal_runtime_state_detaches_hostile_node_stage_flow_text():
    owner = temporal_state.temporal_owner()
    with owner.lock:
        owner._state.clear()
        owner._learning_keys.clear()
    node = HostileText(" node-a ")
    stage = HostileText(" stage-c ")
    flow_tag = HostileText(" flow-tag ")

    events, validations = materialize_temporal_events(
        ordered_events=(),
        behavior_flow=(flow_tag,),
        observation_id="stage1516-hostile-text",
        previous_stage="unknown",
        current_stage=stage,
    )
    assert tuple(record.status for record in validations) == ("valid",)
    request = temporal_v5_request(
        node_id=temporal_state.temporal_state_node_key(node),
        events=events,
    )
    assert temporal_state.commit_temporal_learning_request(request) is True

    snapshot = temporal_state.temporal_node_state_snapshot(node)
    assert len(snapshot["history"]) == 1
    event = snapshot["history"][0]
    assert event.stage == "stage-c"
    assert event.behavior_id == "flow-tag"
    assert event.timestamp_kind == "ordinal_only"
    assert snapshot["hidden_state"]["schema_version"] == "temporal_accumulator_state_v5"
    temporal_state.prune_temporal_state_for_retention(
        max_nodes=1, max_history_per_node=1,
    )
    retained = temporal_state.temporal_history_snapshot(node)
    assert retained == (event,)
    for value in (node, stage, flow_tag):
        assert value.strip_calls == 0
        assert value.bool_calls == 0


def test_stage1516_temporal_runtime_blank_hostile_text_is_explicitly_unavailable():
    owner = temporal_state.temporal_owner()
    with owner.lock:
        owner._state.clear()
        owner._learning_keys.clear()
    blank_node = HostileText("   ")
    blank_stage = HostileText("   ")
    blank_flow = HostileText("   ")

    events, validations = materialize_temporal_events(
        ordered_events=(),
        behavior_flow=(blank_flow,),
        observation_id="stage1516-blank-hostile-text",
        previous_stage="unknown",
        current_stage=blank_stage,
    )

    assert events == ()
    assert validations[0].status == "unavailable"
    assert validations[0].reasons == ("temporal_behavior_unavailable",)
    assert temporal_state.temporal_state_node_key(blank_node) == "<HostileText>"
    assert temporal_state.temporal_has_node(blank_node) is False
    for value in (blank_node, blank_stage, blank_flow):
        assert value.strip_calls == 0
        assert value.bool_calls == 0
