"""Stage 1475: scalar Markov flow inputs cannot become fake transitions."""

from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

from collections import Counter, defaultdict

from Virus_Scan.models.api import markov_contracts
from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
    markov_stage_transition_key,
)
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    runtime_model_mapping_snapshot,
)


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage1475_markov_scalar_string_is_one_event_not_character_flow() -> None:
    flow = markov_contracts.canonical_behavior_flow("download")

    assert flow == ("download",)

    update = markov_contracts.update_markov_model("archive", "download", "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))
    assert update["learned"] is False
    assert update["reason"] == "insufficient_behavior_flow"
    assert update["flow"] == ("download",)


def test_stage1475_markov_scalar_mapping_is_one_observation_not_key_flow() -> None:
    flow = markov_contracts.canonical_behavior_flow({"tag": "api_loadurl"})

    assert flow == ("loadurl",)

    probability = markov_contracts.markov_stage_probability(
        "archive",
        {"tag": "api_loadurl"},
        "runtime",
    )
    assert probability["ready"] is False
    assert probability["probability"] is None
    assert probability["reason"] == "insufficient_behavior_flow"
    assert probability["flow"] == ("loadurl",)


def test_stage1475_markov_sequence_learning_still_records_real_ordered_pairs() -> None:
    _reset_markov_state()

    update = markov_contracts.update_markov_model(
        "archive",
        ("download", "exec"),
        "runtime",
     learning_decision=accepted_learning_decision(target_names=("markov",)))

    assert update["learned"] is True
    assert update["flow"] == ("download", "exec")
    assert update["transitions"] == 1
    snapshot = runtime_model_mapping_snapshot("TRANSITION_COUNTS")
    context = markov_global_context_key()
    assert snapshot[markov_stage_transition_key(
        context_key=context, previous_stage="archive", behavior_flow=("download", "exec"),
    )]["runtime"] == 1
    assert snapshot[markov_event_transition_key(
        context_key=context, previous_stage="archive", source_event="download",
    )]["exec"] == 1
