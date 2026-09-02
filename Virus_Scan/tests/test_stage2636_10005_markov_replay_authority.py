"""Stage2636.01 accepted-learning runtime telemetry has no second Markov owner."""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from Virus_Scan.models.replay.transaction_projection import project_runtime_transaction_stats
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    runtime_markov_observation_total,
    runtime_model_mapping_snapshot,
)
from Virus_Scan.tests.support.profile_learning import (
    accepted_learning_request,
    accepted_runtime_transaction_result,
)


def _reset_runtime_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def _accepted_result(*, reused: bool = False) -> dict[str, object]:
    request = accepted_learning_request(
        Path("stage2636_replay.rpy"),
        flow=("decode", "exec"),
        observation_id="stage2636.01-replay-authority",
        previous_stage="asset",
        current_stage="runtime",
    )
    return accepted_runtime_transaction_result(request, reused=reused)


def test_stage2636_runtime_projection_requires_promoted_transaction() -> None:
    _reset_runtime_state()
    summary = {"runtime": 0}

    stats = project_runtime_transaction_stats({}, summary)

    assert stats["reason"] == "profile_promotion_required"
    assert stats["model_updates_authorized"] is False
    assert stats["runtime_committed"] is False
    assert summary["runtime"] == 0
    assert runtime_markov_observation_total() == 0
    assert dict(runtime_model_mapping_snapshot("TRANSITION_COUNTS")) == {}


def test_stage2636_runtime_projection_never_reexecutes_markov_owner() -> None:
    _reset_runtime_state()
    before = runtime_model_mapping_snapshot("TRANSITION_COUNTS")

    first = project_runtime_transaction_stats(
        _accepted_result(), {"runtime": 0},
    )
    second = project_runtime_transaction_stats(
        _accepted_result(reused=True), {"runtime": 0},
    )
    after = runtime_model_mapping_snapshot("TRANSITION_COUNTS")

    assert first["runtime_committed"] is True
    assert first["markov"] is True
    assert first["markov_mutated"] is True
    assert first["idempotent_replay"] is False
    assert second["runtime_committed"] is True
    assert second["markov"] is True
    assert second["markov_mutated"] is False
    assert second["idempotent_replay"] is True
    assert after == before
    assert runtime_markov_observation_total() == 0
