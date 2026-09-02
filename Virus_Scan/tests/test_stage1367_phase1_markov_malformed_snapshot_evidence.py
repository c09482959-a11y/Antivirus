from __future__ import annotations

import json

from Virus_Scan.models import markov
from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
)
from Virus_Scan.models.contracts.probability_record import materialize_probability_record


def test_stage1367_markov_pair_probability_reports_non_mapping_transition_counter() -> None:
    snapshot = {
        markov_event_transition_key(
            context_key=markov_global_context_key(), previous_stage="asset", source_event="download",
        ): ["not", "a", "counter"],
    }

    record = markov.markov_pair_probability("download", "exec", prev_stage="asset", snapshot=snapshot)
    materialized = materialize_probability_record(record)

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "non_mapping_markov_transition_counter"
    assert record["support"] == 0
    assert record["count"] == 0
    assert record["vocab"] == 2
    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["reason"] == "non_mapping_markov_transition_counter"
    json.dumps(materialized, allow_nan=False, sort_keys=True)


def test_stage1367_markov_stage_probability_reports_non_mapping_snapshot() -> None:
    record = markov.markov_stage_probability(
        "asset",
        ["download", "exec"],
        "runtime",
        snapshot=[("not", "a", "snapshot")],
    )
    materialized = materialize_probability_record(record)

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "non_mapping_markov_snapshot"
    assert record["flow"] == ("download", "exec")
    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["reason"] == "non_mapping_markov_snapshot"
    json.dumps(materialized, allow_nan=False, sort_keys=True)


def test_stage1367_missing_markov_snapshot_key_remains_cold_start_not_malformed() -> None:
    record = markov.markov_pair_probability("download", "exec", prev_stage="asset", snapshot={})

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "insufficient_markov_pair_support"
    json.dumps(materialize_probability_record(record), allow_nan=False, sort_keys=True)
