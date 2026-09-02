from __future__ import annotations

from collections import Counter, defaultdict

from Virus_Scan.models import markov
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
)
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    prune_runtime_model_mappings_for_retention,
    runtime_model_snapshot,
    runtime_transition_key_to_json,
)


class _BadText:
    def __str__(self):  # pragma: no cover - executed by production boundary
        raise RuntimeError("bad str")

    def __repr__(self):  # pragma: no cover - executed by production boundary
        raise RuntimeError("bad repr")


class _HostileMapping(dict):
    def items(self):  # pragma: no cover - executed by production boundary
        raise RuntimeError("bad items")

    def keys(self):  # pragma: no cover - executed by production boundary
        raise RuntimeError("bad keys")

    def __iter__(self):  # pragma: no cover - executed by production boundary
        raise RuntimeError("bad iter")


def _reset_runtime_model_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage1408_runtime_model_snapshot_records_hostile_identity_evidence():
    bad = _BadText()
    try:
        configure_runtime_model_state(
            transition_counts={("stage", frozenset({"known"})): Counter({bad: 1})},
            global_tag_baseline={bad: 1},
            global_tag_pair_baseline={(bad, "known"): 1},
            filetype_baseline={bad: Counter({bad: 1})},
        )

        snapshot = runtime_model_snapshot(
            markov_key_to_json=runtime_transition_key_to_json,
            cluster_state_to_json=lambda: {},
        )
    finally:
        _reset_runtime_model_state()

    assert snapshot["transition_counts"] == []
    assert snapshot["global_tag_baseline"] == {}
    assert snapshot["global_tag_pair_baseline"] == []
    assert snapshot["filetype_baseline"] == {}
    reasons = {row["reason"] for row in snapshot["model_state_unavailable_reasons"]}
    assert "invalid_runtime_transition_type" in reasons
    assert "invalid_runtime_tag_key" in reasons
    assert "invalid_runtime_pair_key" in reasons
    assert "invalid_runtime_filetype_key" in reasons
    assert all("<unrepresentable:" in row.get("value", "") for row in snapshot["model_state_unavailable_reasons"])


def test_stage1408_runtime_model_retention_handles_hostile_mapping_state():
    try:
        configure_runtime_model_state(
            transition_counts={markov_event_transition_key(context_key=markov_global_context_key(), previous_stage="asset", source_event="a"): _HostileMapping()},
            global_tag_baseline=_HostileMapping(),
            global_tag_pair_baseline=_HostileMapping(),
            filetype_baseline={"txt": _HostileMapping()},
        )

        prune_runtime_model_mappings_for_retention(
            max_transition_keys=1,
            max_transition_next_keys=1,
            max_tag_counter_keys=1,
            max_pair_counter_keys=1,
            max_filetype_baselines=1,
        )

        snapshot = runtime_model_snapshot(
            markov_key_to_json=runtime_transition_key_to_json,
            cluster_state_to_json=lambda: {},
        )
    finally:
        _reset_runtime_model_state()

    assert snapshot["transition_counts"] == []
    assert snapshot["global_tag_baseline"] == {}
    assert snapshot["global_tag_pair_baseline"] == []
    assert snapshot["filetype_baseline"] == {}


def test_stage1408_runtime_model_learning_rejects_hostile_flow_as_typed_model_input_failure():
    bad = _BadText()
    try:
        _reset_runtime_model_state()
        result = markov.update_markov_model(
            "asset", (bad, "b"), "runtime",
            learning_decision=accepted_learning_decision(
                target_names=("markov",), observation_id="hostile-flow",
            ),
        )
        assert result["learned"] is False
        assert result["reason"] in {"insufficient_behavior_flow", "markov_update_request_invalid"}
    finally:
        _reset_runtime_model_state()
