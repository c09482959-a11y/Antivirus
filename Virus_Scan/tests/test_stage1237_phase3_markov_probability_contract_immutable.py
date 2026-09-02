from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.tests.support.static_inventory import read_python_file


from collections import Counter, defaultdict

import pytest
from pathlib import Path

from Virus_Scan.models import markov
from Virus_Scan.models.contracts.probability_record import materialize_probability_record
from Virus_Scan.runtime.model_state import configure_runtime_model_state


def _reset_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_markov_probability_records_are_immutable_contract_mappings() -> None:
    _reset_state()
    for _ in range(3):
        assert markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",), observation_id=f"stage1237-markov-{_}"))["learned"] is True

    record = markov.markov_stage_probability("asset", ["download", "exec"], "runtime")

    assert record["ready"] is True
    assert record["probability"] == 0.875
    assert record["flow"] == ("download", "exec")
    with pytest.raises(TypeError):
        record["probability"] = 0.0  # type: ignore[index]


def test_markov_probability_materialization_is_deterministic_and_detached() -> None:
    _reset_state()
    cold = markov.markov_pair_probability("download", "exec", prev_stage="asset")

    first = materialize_probability_record(cold)
    second = materialize_probability_record(cold)

    assert first == second
    assert first["ready"] is False
    assert first["probability"] is None
    assert first["support"] == 0
    assert first["count"] == 0
    assert first["smoothing"] == "jeffreys_dirichlet"
    assert first["reason"] == "insufficient_markov_pair_support"
    assert first["model_version"] == "markov_contextual_dirichlet_v2"
    assert first["alpha"] == 0.5
    assert first["unseen_bucket_count"] == 1
    assert first["previous_stage"] == "asset"
    first["ready"] = True
    assert cold["ready"] is False


def test_markov_probability_record_construction_is_owned_by_model_contract() -> None:
    probability_source = read_python_file(Path("Virus_Scan/models/markov/probability.py"))
    posterior_source = read_python_file(Path("Virus_Scan/models/markov/posterior.py"))

    assert "def _markov_probability_record" not in probability_source
    assert "def _markov_probability_record" not in posterior_source
    assert "from Virus_Scan.models.contracts.probability_record import make_markov_probability_record" in posterior_source
    assert "make_markov_probability_record(" in posterior_source
