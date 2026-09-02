"""Stage 1488: parent replay learning payload detaches optional model fields."""

from __future__ import annotations

from Virus_Scan.models.replay.api import result_learning_payload


class HostileStageText:
    str_calls = 0

    def __str__(self) -> str:  # pragma: no cover - failure if invoked
        type(self).str_calls += 1
        raise RuntimeError("parent replay payload must not call stage __str__")

    def __bool__(self):  # pragma: no cover - failure if unbounded fallback probes it
        raise RuntimeError("parent replay payload must not truth-test stage text")


class HostilePrevStageText:
    str_calls = 0

    def __str__(self) -> str:  # pragma: no cover - failure if invoked
        type(self).str_calls += 1
        raise RuntimeError("parent replay payload must not call previous-stage __str__")

    def __bool__(self):  # pragma: no cover - failure if unbounded fallback probes it
        raise RuntimeError("parent replay payload must not truth-test previous stage text")


class HostileProfileSelection(dict):
    def get(self, key, default=None):  # pragma: no cover - failure if caller mapping is retained
        raise RuntimeError("parent replay payload must detach profile selection before reading it")

    def __bool__(self):  # pragma: no cover - failure if caller mapping is truth-tested
        raise RuntimeError("parent replay payload must not truth-test profile selection")


def _base_result(**updates):
    result = {
        "file": "sample.py",
        "classification": "benign",
        "score": 1.0,
        "tags": ["normal_tag"],
        "engine_context": {"other": 1.0},
        "scan_integrity": {"allow_learning": True},
    }
    result.update(updates)
    return result


def test_stage1488_parent_replay_payload_bounds_stage_truthiness_fallbacks() -> None:
    HostileStageText.str_calls = 0
    HostilePrevStageText.str_calls = 0
    payload = result_learning_payload(
        _base_result(
            effective_stage=HostileStageText(),
            previous_stage=HostilePrevStageText(),
        )
    )

    assert payload is not None
    assert payload["curr_stage"] == "runtime"
    assert payload["prev_stage"] == "unknown"
    assert "reason" not in payload
    assert HostileStageText.str_calls == 0
    assert HostilePrevStageText.str_calls == 0


def test_stage1488_parent_replay_payload_detaches_profile_selection_before_reading() -> None:
    payload = result_learning_payload(
        _base_result(
            profile_selection=HostileProfileSelection({"active_profile": "renpy"}),
            engine_context={"renpy": 1.0},
        )
    )

    assert payload is not None
    assert payload["engine"] == "renpy"
    assert payload["engine_context"] == {"renpy": 1.0}
