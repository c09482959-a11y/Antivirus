from __future__ import annotations
from Virus_Scan.tests.support.runtime_model_state import current_runtime_model_record

from collections import Counter, defaultdict

from Virus_Scan.models import markov
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    load_runtime_model_baselines,
    runtime_model_mapping_snapshot,
    runtime_transition_key_from_json,
)


class HostileSequence:
    def __bool__(self):
        raise RuntimeError("truthiness unavailable")

    def __iter__(self):
        raise RuntimeError("iteration unavailable")


class HostileText:
    def __str__(self):
        raise RuntimeError("text unavailable")


def _reset_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage1418_runtime_model_baseline_loader_rejects_hostile_sequences_without_truthiness():
    _reset_state()

    result = load_runtime_model_baselines(
        current_runtime_model_record({
            "transition_counts": [
                {
                    "type": "markov_event_v2",
                    "context": HostileSequence(),
                    "previous_stage": "asset",
                    "source_event": "decode",
                    "target": "exec",
                    "count": 2,
                }
            ],
            "global_tag_pair_baseline": HostileSequence(),
        })
    )

    assert result["loaded"] is False
    assert result["reason"] == "runtime_model_pair_section_invalid"
    assert runtime_model_mapping_snapshot("TRANSITION_COUNTS") == {}


def test_stage1418_runtime_markov_learning_rejects_hostile_flow_without_mutating_state():
    _reset_state()
    result = markov.update_markov_model(
        "asset", HostileSequence(), "runtime",
        learning_decision=accepted_learning_decision(
            target_names=("markov",), observation_id="hostile-sequence",
        ),
    )

    assert result["learned"] is False
    assert result["reason"] == "insufficient_behavior_flow"

    assert runtime_model_mapping_snapshot("TRANSITION_COUNTS") == {}


def test_stage1418_runtime_transition_key_from_json_hostile_context_degrades_without_hooks():
    key = runtime_transition_key_from_json({
        "type": "markov_event_v2",
        "context": HostileSequence(),
        "previous_stage": "asset",
        "source_event": "decode",
    })

    assert key == ("markov_event_v2", ("", "asset", "decode"))
