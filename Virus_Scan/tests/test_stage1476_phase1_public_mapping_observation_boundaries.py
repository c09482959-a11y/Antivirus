"""Stage 1476: public model sequence boundaries preserve mapping observations.

A detection observation mapping is a single behavior observation, not an iterable
of mapping keys. Public model facades must not convert ``{"tag": ...}`` into
``("tag",)`` or reject it as malformed before canonical model owners can
normalize the behavior event.
"""

from __future__ import annotations
import math
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

from collections import Counter, defaultdict

from Virus_Scan.models import profiles
from Virus_Scan.models.api import adaptive_signals, markov_contracts, profile_learning_contracts, temporal_contracts
from Virus_Scan.runtime.model_state import configure_runtime_model_state


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage1476_adaptive_public_flow_treats_mapping_as_single_observation() -> None:
    direct = markov_contracts.canonical_behavior_flow({"tag": "api_loadurl"})
    public = adaptive_signals.canonical_behavior_flow({"tag": "api_loadurl"})

    assert direct == ("loadurl",)
    assert public == direct
    assert public != ("tag",)


def test_stage1476_temporal_public_overlay_accepts_mapping_observation_without_key_flow() -> None:
    _reset_markov_state()

    overlay = temporal_contracts.transition_probability_overlay(
        prev_stage="asset",
        tags=({"tag": "api_download"}, {"tag": "api_exec"}),
        curr_stage="runtime",
        ordered_events=(
            {"tag": "api_download", "timestamp": 1.0, "stage": "asset"},
            {"tag": "api_exec", "timestamp": 2.0, "stage": "runtime"},
        ),
    )

    assert overlay["flow"] == ("download", "exec")
    assert overlay["probability_ready"] is False
    assert overlay["stage_probability"] is None
    assert overlay["unavailable_reason"] == "insufficient_markov_stage_support"
    assert overlay["pair_probabilities"][0]["from"] == "download"
    assert overlay["pair_probabilities"][0]["to"] == "exec"
    assert overlay["pair_probabilities"][0]["reason"] == "insufficient_markov_pair_support"


def test_stage1476_profile_public_and_direct_flows_extract_mapping_observation_tags() -> None:
    observation = {"tag": "api_loadurl"}

    assert profiles.canonical_behavior_flow_from_sources(raw_tags=observation) == ["api_loadurl"]
    assert profile_learning_contracts.canonical_behavior_flow_from_sources(raw_tags=observation) == ["api_loadurl"]
    assert profiles.canonical_profile_learning_flow(tags=observation) == ["api_loadurl"]
    assert profiles.real_ordered_event_names(observation) == ["api_loadurl"]


def test_stage1476_temporal_public_overlay_mapping_sequence_uses_trained_support() -> None:
    _reset_markov_state()
    flow = ({"tag": "api_download"}, {"tag": "api_exec"})
    for _ in range(3):
        assert markov_contracts.update_markov_model("asset", flow, "runtime", learning_decision=accepted_learning_decision(target_names=("markov",), observation_id=f"stage1476-markov-{_}"))["learned"] is True

    overlay = temporal_contracts.transition_probability_overlay(
        prev_stage="asset",
        tags=flow,
        curr_stage="runtime",
        ordered_events=(
            {"tag": "api_download", "timestamp": 10.0, "stage": "asset"},
            {"tag": "api_exec", "timestamp": 12.0, "stage": "runtime"},
        ),
    )

    assert overlay["flow"] == ("download", "exec")
    assert overlay["probability_ready"] is True
    assert overlay["stage_probability_ready"] is True
    assert math.isclose(overlay["stage_probability"], 7.0 / 8.0)
    assert math.isclose(overlay["sequence_probability"], 7.0 / math.sqrt(72.0), abs_tol=1e-6)
    assert overlay["stage_probability"] < 1.0
    assert overlay["sequence_probability"] < 1.0
    assert overlay["cold_start_reason"] is None

from Virus_Scan.models.api import graph_contracts
from Virus_Scan.models.profiles.common import profile_public_tags
from Virus_Scan.utils.tagging import canonical_raw_tag_list, ordered_unique_tags


def test_stage1476_tag_normalizers_extract_mapping_observation_tag_not_key() -> None:
    observation = {"tag": "api_download"}

    assert ordered_unique_tags(observation) == ["api_download"]
    assert canonical_raw_tag_list(observation) == ["api_download"]
    assert profile_public_tags(observation) == (("api_download",), None)


def test_stage1476_graph_temporal_link_public_boundary_preserves_mapping_flow() -> None:
    result = graph_contracts.link_temporal_to_graph(
        "stage1476-node",
        "asset",
        ({"tag": "api_download"}, {"tag": "api_exec"}),
        "runtime",
    )

    assert result["linked"] is True
    assert result["flow"] == ("download", "exec")
