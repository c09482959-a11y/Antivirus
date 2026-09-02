from __future__ import annotations

import json
import math

from Virus_Scan.models import markov
from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
    markov_stage_transition_key,
)
from Virus_Scan.models.contracts.probability_record import materialize_probability_record


def test_stage1324_markov_pair_probability_rejects_nonfinite_snapshot_counts_without_crashing():
    snapshot = {
        markov_event_transition_key(
            context_key=markov_global_context_key(),
            previous_stage="asset",
            source_event="download",
        ): {
            "exec": math.inf,
            "archive": 1,
        }
    }

    record = markov.markov_pair_probability("download", "exec", prev_stage="asset", snapshot=snapshot)
    materialized = materialize_probability_record(record)

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "non_finite_markov_count"
    assert materialized["ready"] is False
    assert materialized["probability"] is None
    json.dumps(materialized, allow_nan=False, sort_keys=True)


def test_stage1324_markov_stage_probability_rejects_nonfinite_snapshot_counts_without_crashing():
    snapshot = {
        markov_stage_transition_key(
            context_key=markov_global_context_key(),
            previous_stage="asset",
            behavior_flow=("download", "exec"),
        ): {
            "runtime": math.nan,
            "archive": 3,
        }
    }

    record = markov.markov_stage_probability(
        "asset",
        ["download", "exec"],
        "runtime",
        snapshot=snapshot,
    )
    materialized = materialize_probability_record(record)

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "non_finite_markov_count"
    assert record["flow"] == ("download", "exec")
    assert materialized["ready"] is False
    assert materialized["probability"] is None
    json.dumps(materialized, allow_nan=False, sort_keys=True)


def test_stage1324_markov_probability_preserves_valid_snapshot_counts():
    pair_snapshot = {
        markov_event_transition_key(
            context_key=markov_global_context_key(),
            previous_stage="asset",
            source_event="download",
        ): {
            "exec": 3,
            "archive": 1,
        }
    }
    stage_snapshot = {
        markov_stage_transition_key(
            context_key=markov_global_context_key(),
            previous_stage="asset",
            behavior_flow=("download", "exec"),
        ): {
            "runtime": 3,
            "archive": 1,
        }
    }

    pair = markov.markov_pair_probability("download", "exec", prev_stage="asset", snapshot=pair_snapshot)
    stage = markov.markov_stage_probability(
        "asset",
        ["download", "exec"],
        "runtime",
        snapshot=stage_snapshot,
    )

    assert pair["ready"] is True
    assert pair["probability"] == 3.5 / 5.5
    assert pair["support"] == 4
    assert pair["count"] == 3
    assert stage["ready"] is True
    assert stage["probability"] == 3.5 / 5.5
    assert stage["support"] == 4
    assert stage["count"] == 3
    json.dumps(materialize_probability_record(pair), allow_nan=False, sort_keys=True)
    json.dumps(materialize_probability_record(stage), allow_nan=False, sort_keys=True)
