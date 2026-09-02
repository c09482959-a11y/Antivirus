"""Stage 1370 Phase 1 runtime model identity validation regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.runtime_model_state import current_runtime_model_record

import json
from collections import Counter, defaultdict

from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    load_runtime_model_baselines,
    runtime_model_mapping_snapshot,
    runtime_model_snapshot,
    runtime_transition_key_to_json,
)


def test_stage1370_runtime_model_snapshot_omits_empty_global_and_filetype_keys() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline={"": 7, "download": 3},
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline={"": Counter({"download": 2}), ".bin": Counter({"": 4, "exec": 5})},
    )

    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    reasons = snapshot["model_state_unavailable_reasons"]
    assert any(item["reason"] == "invalid_runtime_tag_key" for item in reasons)
    assert any(item["reason"] == "invalid_runtime_filetype_key" for item in reasons)
    assert any(item["reason"] == "invalid_runtime_filetype_tag_key" for item in reasons)
    assert snapshot["global_tag_baseline"] == {"download": 3}
    assert snapshot["filetype_baseline"] == {".bin": {"exec": 5}}
    json.dumps(snapshot, allow_nan=False, sort_keys=True)


def test_stage1370_runtime_model_loader_rejects_empty_global_and_filetype_keys() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )

    result = load_runtime_model_baselines(
        current_runtime_model_record({
            "global_tag_baseline": {"": 7, "download": 3},
            "filetype_baseline": {"": {"download": 2}, ".bin": {"": 4, "exec": 5}},
        })
    )

    assert result["loaded"] is False
    assert result["reason"] == "runtime_model_snapshot_key_invalid"
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE") == {}
    assert runtime_model_mapping_snapshot("FILETYPE_BASELINE") == {}
