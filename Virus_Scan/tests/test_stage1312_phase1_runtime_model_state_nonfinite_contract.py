from __future__ import annotations
from Virus_Scan.tests.support.runtime_model_state import current_runtime_model_record

import json
import math
from collections import Counter, defaultdict

from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
    markov_stage_transition_key,
)
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    load_runtime_model_baselines,
    runtime_model_mapping_snapshot,
    runtime_model_snapshot,
    runtime_transition_key_to_json,
)


def _reset_state(*, transition_counts=None, global_tag_baseline=None, global_tag_pair_baseline=None, filetype_baseline=None) -> None:
    configure_runtime_model_state(
        transition_counts=transition_counts if transition_counts is not None else defaultdict(Counter),
        global_tag_baseline=global_tag_baseline if global_tag_baseline is not None else defaultdict(int),
        global_tag_pair_baseline=global_tag_pair_baseline if global_tag_pair_baseline is not None else defaultdict(int),
        filetype_baseline=filetype_baseline if filetype_baseline is not None else defaultdict(Counter),
    )


def test_stage1312_runtime_model_snapshots_sanitize_nonfinite_learned_counts() -> None:
    transition_counts = defaultdict(Counter)
    context = markov_global_context_key()
    transition_counts[markov_stage_transition_key(
        context_key=context, previous_stage="asset", behavior_flow=("download", "exec"),
    )]["runtime"] = math.inf
    transition_counts[markov_event_transition_key(
        context_key=context, previous_stage="asset", source_event="download",
    )]["exec"] = math.nan

    _reset_state(
        transition_counts=transition_counts,
        global_tag_baseline={"download": math.nan, "exec": -math.inf},
        global_tag_pair_baseline={("download", "exec"): math.inf},
        filetype_baseline={".bin": Counter({"download": math.nan, "exec": 2})},
    )

    baseline_snapshot = runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE")
    assert dict(baseline_snapshot) == {}

    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert snapshot["transition_counts"] == []
    assert snapshot["global_tag_baseline"] == {}
    assert snapshot["global_tag_pair_baseline"] == []
    assert snapshot["filetype_baseline"] == {".bin": {"exec": 2}}
    reasons = snapshot["model_state_unavailable_reasons"]
    assert any(item["reason"] == "non_finite_runtime_model_count" for item in reasons)
    json.dumps(snapshot, allow_nan=False, sort_keys=True)


def test_stage1312_runtime_model_baseline_loader_rejects_nonfinite_counts_without_crashing() -> None:
    _reset_state()
    result = load_runtime_model_baselines(
        current_runtime_model_record({
            "transition_counts": [
                {"type": "markov_stage_v2", "context": "global:trusted_benign", "previous_stage": "asset", "flow_class": "flow:test", "target": "runtime", "count": math.inf},
                {"type": "markov_stage_v2", "context": "global:trusted_benign", "previous_stage": "asset", "flow_class": "flow:test", "target": "runtime", "count": 3},
            ],
            "global_tag_baseline": {"download": math.nan, "exec": 4},
            "global_tag_pair_baseline": [
                {"a": "download", "b": "exec", "count": -math.inf},
                {"a": "exec", "b": "persist", "count": 2},
            ],
            "filetype_baseline": {".bin": {"download": math.nan, "exec": 5}},
        })
    )
    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )
    assert result["loaded"] is False
    assert result["reason"] == "runtime_model_snapshot_nonfinite"
    assert snapshot["transition_counts"] == []
    assert snapshot["global_tag_baseline"] == {}
    assert snapshot["global_tag_pair_baseline"] == []
    assert snapshot["filetype_baseline"] == {}
    json.dumps(snapshot, allow_nan=False, sort_keys=True)

