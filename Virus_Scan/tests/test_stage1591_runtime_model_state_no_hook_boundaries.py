from __future__ import annotations
from Virus_Scan.tests.support.runtime_model_state import current_runtime_model_record

import json
from collections import Counter, defaultdict
from collections.abc import Mapping

from Virus_Scan.contracts.markov_learning import (
    markov_global_context_key,
    markov_stage_transition_key,
)
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    load_runtime_model_baselines,
    runtime_model_snapshot,
    runtime_transition_key_to_json,
)


class HostileRuntimeMapping(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate runtime mapping")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not len runtime mapping")

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("do not index runtime mapping")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not get runtime mapping")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not items runtime mapping")

    def keys(self):
        type(self).touched += 1
        raise RuntimeError("do not keys runtime mapping")


class HostileRuntimeIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate runtime iterable")


class HostileRuntimeText:
    touched = 0

    def __hash__(self):
        return 1591

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify runtime text")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr runtime text")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("do not format runtime text")


def _reset_runtime_model_state(**overrides) -> None:
    configure_runtime_model_state(
        transition_counts=overrides.get("transition_counts", defaultdict(Counter)),
        global_tag_baseline=overrides.get("global_tag_baseline", defaultdict(int)),
        global_tag_pair_baseline=overrides.get("global_tag_pair_baseline", defaultdict(int)),
        filetype_baseline=overrides.get("filetype_baseline", defaultdict(Counter)),
    )


def test_stage1591_runtime_model_loader_rejects_hostile_top_mapping_without_hooks() -> None:
    HostileRuntimeMapping.touched = 0
    _reset_runtime_model_state(global_tag_baseline={"download": 3})

    result = load_runtime_model_baselines(HostileRuntimeMapping())

    assert HostileRuntimeMapping.touched == 0
    assert result["loaded"] is False
    assert result["reason"] == "runtime_model_snapshot_record_invalid"
    assert result["model_state_unavailable_reasons"][0]["reason"] == "runtime_model_snapshot_record_invalid"


def test_stage1591_runtime_model_snapshot_rejects_hostile_counter_without_mapping_hooks() -> None:
    HostileRuntimeMapping.touched = 0
    transition_counts = {
        markov_stage_transition_key(
            context_key=markov_global_context_key(),
            previous_stage="asset",
            behavior_flow=("download", "exec"),
        ): HostileRuntimeMapping(),
    }
    _reset_runtime_model_state(transition_counts=transition_counts)

    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert HostileRuntimeMapping.touched == 0
    assert snapshot["transition_counts"] == []
    assert any(
        item["reason"] == "non_mapping_runtime_transition_counter"
        for item in snapshot["model_state_unavailable_reasons"]
    )
    json.dumps(snapshot, allow_nan=False, sort_keys=True)


def test_stage1591_runtime_model_loader_rejects_hostile_flow_without_iteration() -> None:
    HostileRuntimeIterable.touched = 0
    _reset_runtime_model_state()

    result = load_runtime_model_baselines(
        current_runtime_model_record({
            "transition_counts": [
                {
                    "type": "markov_stage_v2",
                    "context": HostileRuntimeIterable(),
                    "previous_stage": "asset",
                    "flow_class": "flow:test",
                    "target": "runtime",
                    "count": 3,
                }
            ]
        })
    )

    assert HostileRuntimeIterable.touched == 0
    assert result["loaded"] is False
    assert result["reason"] == "runtime_model_snapshot_value_invalid"


def test_stage1591_runtime_model_snapshot_rejects_hostile_identity_without_text_hooks() -> None:
    HostileRuntimeText.touched = 0
    hostile = HostileRuntimeText()
    _reset_runtime_model_state(global_tag_baseline={hostile: 4, "download": 2})

    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert HostileRuntimeText.touched == 0
    assert snapshot["global_tag_baseline"] == {"download": 2}
    assert any(
        item["reason"] == "invalid_runtime_tag_key"
        for item in snapshot["model_state_unavailable_reasons"]
    )
    json.dumps(snapshot, allow_nan=False, sort_keys=True)


def test_stage1973_runtime_model_state_failure_paths_are_explicit_without_hooks() -> None:
    HostileRuntimeMapping.touched = 0
    HostileRuntimeIterable.touched = 0
    HostileRuntimeText.touched = 0
    _reset_runtime_model_state()

    result = load_runtime_model_baselines(
        current_runtime_model_record({
            "transition_counts": [
                HostileRuntimeMapping(),
                {
                    "type": "invalid_transition_type",
                    "context": HostileRuntimeIterable(),
                    "target": "",
                    "count": "bad-count",
                },
            ],
            "global_tag_baseline": {HostileRuntimeText(): "bad-count"},
            "global_tag_pair_baseline": [
                HostileRuntimeMapping(),
                {"a": "", "b": "right", "count": "bad-count"},
            ],
            "filetype_baseline": {"txt": {HostileRuntimeText(): "bad-count"}},
        })
    )

    assert HostileRuntimeMapping.touched == 0
    assert HostileRuntimeIterable.touched == 0
    assert HostileRuntimeText.touched == 0
    assert result["loaded"] is False
    assert result["reason"] in {
        "runtime_model_snapshot_value_invalid",
        "runtime_model_snapshot_key_invalid",
    }
