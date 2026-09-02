from __future__ import annotations

from collections import Counter, defaultdict

from Virus_Scan.contracts.temporal_accumulator import initial_temporal_accumulator_state
from Virus_Scan.models.temporal import update_temporal
from Virus_Scan.models.temporal.accumulator import temporal_evidence_accumulator_update
from Virus_Scan.models.temporal.overlay import (
    temporal_markov_overlay_support,
    transition_probability_overlay,
)
from Virus_Scan.runtime.model_state import configure_runtime_model_state
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


class HostileBoolFlow:
    touched = 0
    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("temporal owner must not iterate caller-owned flow")
    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("temporal owner must not truth-test caller-owned flow")


class HostileBoolStage:
    touched = 0
    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("temporal owner must not stringify caller-owned stage")
    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("temporal owner must not truth-test caller-owned stage")


class HostileBoolTimes:
    touched = 0
    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("temporal owner must not iterate caller-owned events")
    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("temporal owner must not truth-test caller-owned events")


class HostileNumeric:
    touched = 0
    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("temporal accumulator must not truth-test scalar")
    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("temporal accumulator must not convert scalar")


def test_stage1481_temporal_markov_overlay_support_rejects_hostile_flow_without_hooks() -> None:
    _reset_markov_state()
    HostileBoolFlow.touched = HostileBoolStage.touched = 0
    support = temporal_markov_overlay_support(
        HostileBoolStage(), HostileBoolFlow(), "runtime",
    )

    assert HostileBoolFlow.touched == 0
    assert HostileBoolStage.touched == 0
    assert support["ready"] is False
    assert support["stage_probability_record"]["probability"] is None
    assert support["stage_probability_record"]["ready"] is False
    assert support["pair_probability_records"] == ()
    assert support["reason"] == "insufficient_behavior_flow"
    assert support["features"]["flow"] == ()


def test_stage1481_temporal_overlay_rejects_hostile_flow_and_events_without_hooks() -> None:
    _reset_markov_state()
    HostileBoolFlow.touched = HostileBoolTimes.touched = HostileBoolStage.touched = 0
    overlay = transition_probability_overlay(
        prev_stage=HostileBoolStage(), tags=HostileBoolFlow(),
        curr_stage=HostileBoolStage(), ordered_events=HostileBoolTimes(),
    )

    assert overlay["flow"] == ()
    assert overlay["prev_stage"] == "unknown"
    assert overlay["curr_stage"] == "unknown"
    assert overlay["stage_probability"] is None
    assert overlay["probability_ready"] is False
    assert HostileBoolFlow.touched == 0
    assert HostileBoolTimes.touched == 0
    assert HostileBoolStage.touched == 0


def test_stage1481_update_temporal_rejects_hostile_tags_without_hooks() -> None:
    HostileBoolFlow.touched = HostileBoolStage.touched = 0
    result = update_temporal(
        "stage1481-temporal-owner-node", HostileBoolStage(),
        HostileBoolFlow(),
        learning_decision=accepted_learning_decision(target_names=("temporal",)),
    )

    assert result["updated"] is False
    assert result["reason"] == "no_behavior_flow"
    assert result["flow"] == ()
    assert HostileBoolFlow.touched == 0
    assert HostileBoolStage.touched == 0


def test_stage1481_temporal_accumulator_rejects_hostile_scalars_without_hooks() -> None:
    HostileNumeric.touched = 0
    state = temporal_evidence_accumulator_update(
        previous=initial_temporal_accumulator_state(),
        observation=HostileNumeric(), observation_confidence=HostileNumeric(),
        evidence_timestamp=HostileNumeric(), support=0,
    )

    assert state.posterior_belief == 0.0
    assert state.last_evidence_timestamp is None
    assert state.unavailable_reason == "temporal_accumulator_probability_invalid"
    assert HostileNumeric.touched == 0
