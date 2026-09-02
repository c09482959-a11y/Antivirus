from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

from collections import Counter, defaultdict

import pytest

from Virus_Scan.models import markov
from Virus_Scan.models.contracts.model_evidence import materialize_model_evidence_record
from Virus_Scan.runtime.model_state import configure_runtime_model_state


def _reset_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_markov_learning_update_returns_immutable_evidence_record() -> None:
    _reset_state()

    record = markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))

    assert record["learned"] is True
    assert record["flow"] == ("download", "exec")
    assert record["transitions"] == 1
    assert record["reason"] is None
    assert record["model_name"] == "markov"
    assert record["evidence_type"] == "learning_update"
    assert record["model_version"] == "markov_learning_update_v2"
    with pytest.raises(TypeError):
        record["learned"] = False  # type: ignore[index]


def test_markov_learning_update_detaches_caller_owned_flow() -> None:
    _reset_state()
    flow = ["download", "exec"]

    record = markov.update_markov_model("asset", flow, "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))
    flow.append("mutated_after_update")

    assert record["flow"] == ("download", "exec")


def test_markov_learning_update_materialization_is_deterministic_and_detached() -> None:
    _reset_state()

    record = markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))
    first = materialize_model_evidence_record(record)
    second = materialize_model_evidence_record(record)

    assert first == second
    assert first["flow"] == ("download", "exec")
    first["learned"] = False
    assert record["learned"] is True


def test_markov_learning_cold_start_failure_is_explicit_evidence_not_clean_default() -> None:
    _reset_state()

    record = markov.update_markov_model("asset", ["download"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))

    assert record["learned"] is False
    assert record["reason"] == "insufficient_behavior_flow"
    assert record["flow"] == ("download",)
    assert record["transitions"] == 0
    assert record["model_version"] == "markov_learning_update_v2"
