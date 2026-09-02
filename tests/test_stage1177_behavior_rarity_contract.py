from __future__ import annotations

from collections import Counter, defaultdict

from Virus_Scan.contracts.behavior_rarity import behavior_rarity_from_flow
from Virus_Scan.detection.scoring.weighting.behavior_learning import tag_rarity_score
import Virus_Scan.models.markov as markov
from Virus_Scan.models.markov import markov_tag_rarity_score
from Virus_Scan.runtime import model_state
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision


def _reset_runtime_model_state() -> None:
    model_state.configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage1177_shared_behavior_rarity_contract_matches_detection_api():
    baseline = {"decode": 20, "exec": 1, "network": 3}
    assert behavior_rarity_from_flow(("decode", "exec"), baseline) == tag_rarity_score(
        ["decode", "exec"], baseline
    )


def test_stage1177_markov_rarity_uses_runtime_snapshot_owner():
    _reset_runtime_model_state()
    try:
        for ordinal in range(20):
            result = markov.update_markov_model(
                "asset", ("decode", "cache"), "runtime",
                learning_decision=accepted_learning_decision(
                    target_names=("markov",),
                    observation_id=f"stage1177-decode:{ordinal}",
                ),
            )
            assert result["learned"] is True
        result = markov.update_markov_model(
            "asset", ("exec", "cache"), "runtime",
            learning_decision=accepted_learning_decision(
                target_names=("markov",), observation_id="stage1177-exec:0",
            ),
        )
        assert result["learned"] is True

        rarity = markov_tag_rarity_score(["decode", "exec"])
        assert 0.0 < rarity < 1.0
    finally:
        _reset_runtime_model_state()


def test_stage1177_model_markov_no_longer_exposes_duplicate_tag_rarity_name():
    assert not hasattr(markov, "tag_rarity_score")
    assert hasattr(markov, "markov_tag_rarity_score")
