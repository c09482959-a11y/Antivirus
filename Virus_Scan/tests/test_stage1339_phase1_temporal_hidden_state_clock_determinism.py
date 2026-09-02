from __future__ import annotations

import inspect

import Virus_Scan.models.temporal.accumulator as temporal_accumulator
from Virus_Scan.contracts.temporal_accumulator import TemporalAccumulatorState


def _previous_state() -> TemporalAccumulatorState:
    return TemporalAccumulatorState(
        prior_belief=0.6, current_observation=0.6,
        observation_confidence=0.5, elapsed_evidence_time=0.0,
        posterior_belief=0.6, support=4, maturity=1.0,
        last_evidence_timestamp=123.25, unavailable_reason=None,
    )


def test_stage1339_accumulator_without_new_time_is_replay_stable() -> None:
    first = temporal_accumulator.temporal_evidence_accumulator_update(
        previous=_previous_state(), observation=0.4,
        observation_confidence=0.2, evidence_timestamp=None, support=5,
    )
    second = temporal_accumulator.temporal_evidence_accumulator_update(
        previous=_previous_state(), observation=0.4,
        observation_confidence=0.2, evidence_timestamp=None, support=5,
    )

    assert second == first
    assert first.last_evidence_timestamp == 123.25
    assert first.elapsed_evidence_time == 0.0
    assert first.unavailable_reason == "temporal_elapsed_evidence_unavailable"


def test_stage1339_temporal_accumulator_has_no_live_clock_fallback() -> None:
    source = inspect.getsource(
        temporal_accumulator.temporal_evidence_accumulator_update
    )
    module_source = inspect.getsource(temporal_accumulator)

    assert "time.time" not in source
    assert "time.time" not in module_source
    assert "import time" not in module_source
