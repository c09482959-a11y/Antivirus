"""Stage 1370 runtime model mapping snapshot identity regressions."""
from __future__ import annotations

from collections import Counter, defaultdict

from Virus_Scan.models import markov
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    runtime_model_mapping_snapshot,
)


def test_stage1370_runtime_model_mapping_snapshot_omits_invalid_identity_keys() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline={"": 9, "download": 3},
        global_tag_pair_baseline={"download->exec": 99, ("", "exec"): 9, ("download", "exec"): 2},
        filetype_baseline={"": Counter({"download": 7}), ".bin": Counter({"": 3, "exec": 5})},
    )

    assert runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE") == {"download": 3}
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_PAIR_BASELINE") == {("download", "exec"): 2}
    assert runtime_model_mapping_snapshot("FILETYPE_BASELINE") == {".bin": {"exec": 5}}


def test_stage1370_invalid_pair_identity_cannot_make_markov_features_ready() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline={"download": 2, "exec": 2},
        global_tag_pair_baseline={"download->exec": 500},
        filetype_baseline=defaultdict(Counter),
    )

    features = markov.compute_markov_features("asset", ["download", "exec"], "runtime")

    assert features["ready"] is False
    assert features["reason"] == "insufficient_markov_stage_support"
    assert features["supported_transitions"] == 0
    assert features["unavailable_transitions"] == 2
