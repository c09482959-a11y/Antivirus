"""Stage 1401: public model APIs reject malformed iterable inputs safely."""

from __future__ import annotations

import pytest
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

from collections.abc import Mapping

from Virus_Scan.models.api import adaptive_signals, markov_contracts



@pytest.fixture(autouse=True)
def _canonical_profile_bootstrap(tmp_path):
    bind_profile_database(tmp_path)
    ensure_authoritative_engine_profiles()


class NonIterableInput:
    pass


def test_stage1401_markov_public_contracts_do_not_raise_for_non_iterable_flow() -> None:
    value = NonIterableInput()

    assert markov_contracts.canonical_behavior_flow(value) == ()

    features = markov_contracts.compute_markov_features("prev", value, "curr")
    assert isinstance(features, Mapping)
    assert features["ready"] is False
    assert features["reason"] == "insufficient_behavior_flow"

    stage_probability = markov_contracts.markov_stage_probability("prev", value, "curr")
    assert stage_probability["ready"] is False
    assert stage_probability["probability"] is None
    assert stage_probability["reason"] == "insufficient_behavior_flow"

    sequence_probability = markov_contracts.markov_sequence_probability("prev", value, "curr")
    assert sequence_probability["ready"] is False
    assert sequence_probability["probability"] is None
    assert sequence_probability["reason"] == "insufficient_behavior_flow"

    update_record = markov_contracts.update_markov_model("prev", value, "curr", learning_decision=accepted_learning_decision(target_names=("markov",)))
    assert update_record["learned"] is False
    assert update_record["reason"] == "insufficient_behavior_flow"


def test_stage1401_adaptive_public_signal_contracts_do_not_raise_for_non_iterables() -> None:
    value = NonIterableInput()

    assert adaptive_signals.canonical_behavior_flow(value) == ()
    assert adaptive_signals.compute_markov_features("prev", value, "curr")["ready"] is False

    coordinated = adaptive_signals.coordinated_model_validation_signal(
        "other",
        "sample.bin",
        value,
        api_calls=value,
        ordered_events=value,
    )
    assert coordinated["degraded"] is True
    assert coordinated["final_json_must_record"] is True
    assert coordinated["replay_record_required"] is True
    assert "unavailable_reasons" in coordinated
