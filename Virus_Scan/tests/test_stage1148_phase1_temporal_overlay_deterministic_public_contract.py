from __future__ import annotations

import ast
from collections import Counter, defaultdict
from pathlib import Path

from Virus_Scan.models import markov, temporal
from Virus_Scan.runtime.model_state import configure_runtime_model_state
from Virus_Scan.runtime.temporal_state import temporal_node_state_snapshot
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision


def _function_source(path: str, name: str) -> str:
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    return ast.get_source_segment(source, function) or ""


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def _learn_markov(flow: list[str], count: int, prefix: str) -> None:
    for index in range(count):
        result = markov.update_markov_model(
            "asset", flow, "runtime",
            learning_decision=accepted_learning_decision(
                target_names=("markov",), observation_id=f"{prefix}-{index}",
            ),
        )
        assert result["learned"] is True


def test_stage1148_temporal_overlay_public_output_is_deterministic_without_observed_time() -> None:
    _reset_markov_state()
    _learn_markov(["download", "exec"], 3, "stage1148-first")

    kwargs = dict(prev_stage="asset", tags=["download", "exec"], curr_stage="runtime")
    first = temporal.transition_probability_overlay(**kwargs)
    second = temporal.transition_probability_overlay(**kwargs)

    assert first == second
    assert first["probability_ready"] is True
    assert first["degraded"] is False
    assert first["unavailable_reason"] is None
    assert first["observed_time_evidence"] == {
        "ready": False,
        "observed_event_count": 0,
        "reference_timestamp": None,
        "order_only_event_count": 2,
    }
    assert first["hidden_state"]["last_evidence_timestamp"] is None
    assert all(row["elapsed_time_used"] is False for row in first["pair_probabilities"])


def test_stage1148_temporal_overlay_uses_canonical_observed_events_as_deterministic_reference() -> None:
    _reset_markov_state()
    _learn_markov(["download", "exec", "network"], 4, "stage1148-second")

    overlay = temporal.transition_probability_overlay(
        prev_stage="asset",
        tags=["download", "exec", "network"],
        curr_stage="runtime",
        ordered_events=[
            {"tag": "download", "timestamp": 100.0, "stage": "asset"},
            {"tag": "exec", "timestamp": 110.0, "stage": "runtime"},
            {"tag": "network", "timestamp": 150.0, "stage": "runtime"},
        ],
    )

    assert overlay["hidden_state"]["last_evidence_timestamp"] == 150.0
    assert overlay["observed_time_evidence"]["reference_timestamp"] == 150.0
    assert overlay["observed_time_evidence"]["observed_event_count"] == 3
    assert [event["timestamp_value"] for event in overlay["events"]] == [100.0, 110.0, 150.0]
    assert overlay["probability_ready"] is True
    assert overlay["stage_probability_ready"] is True


def test_stage1148_temporal_overlay_source_has_no_live_time_or_legacy_event_time_path() -> None:
    overlay_source = _function_source(
        "Virus_Scan/models/temporal/overlay.py", "transition_probability_overlay",
    )
    materializer_source = _function_source(
        "Virus_Scan/models/temporal/event_materialization.py",
        "materialize_temporal_events",
    )

    assert "time.time()" not in overlay_source + materializer_source
    assert "event_times" not in overlay_source
    assert "materialize_temporal_events" in overlay_source
    assert "timestamp_kind" in materializer_source
    assert "synthetic_order" in materializer_source


def test_stage1148_snapshot_temporal_is_pure_deterministic_projection_not_runtime_mutation() -> None:
    node = "stage1148-snapshot-temporal-pure-projection"
    temporal.update_temporal(
        node, "asset", ["download", "exec"],
        learning_decision=accepted_learning_decision(
            target_names=("temporal",), observation_id="stage1148-state-1",
        ),
    )
    temporal.update_temporal(
        node, "runtime", ["network", "persistence"], previous_stage="asset",
        learning_decision=accepted_learning_decision(
            target_names=("temporal",), observation_id="stage1148-state-2",
        ),
    )

    state_before = dict(temporal_node_state_snapshot(node))
    first = temporal.snapshot_temporal(node)
    state_after_first = dict(temporal_node_state_snapshot(node))
    second = temporal.snapshot_temporal(node)
    state_after_second = dict(temporal_node_state_snapshot(node))

    assert first == second
    assert state_after_first == state_before
    assert state_after_second == state_before
    assert first["ready"] is True
    assert first["hidden_state"]["last_evidence_timestamp"] is None
    assert first["observed_time_evidence"]["ready"] is False


def test_stage1148_snapshot_temporal_source_does_not_mutate_runtime_snapshot_state() -> None:
    source = _function_source(
        "Virus_Scan/models/temporal/state_projection.py", "snapshot_temporal",
    )

    assert "time.time()" not in source
    assert "commit_temporal_learning_request" not in source
    assert "update_temporal_snapshot" not in source
    assert "_observed_reference" in source
