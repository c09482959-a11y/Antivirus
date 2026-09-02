from Virus_Scan.models.replay.api import (
    parent_replay_result_learning,
    result_learning_payload,
)


class _HostileText:
    def __str__(self):  # pragma: no cover - exercised by boundary code
        raise RuntimeError("hostile string conversion")

    def __repr__(self):  # pragma: no cover - exercised by boundary code
        raise RuntimeError("hostile repr conversion")


def test_stage1413_parent_replay_hostile_tag_is_explicitly_degraded_not_learned():
    result = {
        "file": "sample.py",
        "classification": "benign",
        "score": 1.0,
        "tags": [_HostileText(), "normal_tag"],
        "engine_context": {"other": 1.0},
    }

    payload = result_learning_payload(result)
    summary = parent_replay_result_learning(result)

    assert payload == {
        "replay_payload_unavailable": True,
        "reason": "parent_replay_input_unavailable",
    }
    assert summary["degraded"] is True
    assert summary["errors"] == 1
    assert summary["skipped"] == "parent_replay_input_unavailable"
    assert summary["committed"] == 0
    assert summary["runtime"] == 0


def test_stage1413_parent_replay_hostile_identity_is_explicitly_degraded():
    result = {
        "file": _HostileText(),
        "classification": "benign",
        "score": 1.0,
        "tags": ["normal_tag"],
        "engine_context": {"other": 1.0},
    }

    payload = result_learning_payload(result)
    summary = parent_replay_result_learning(result)

    assert payload == {
        "replay_payload_unavailable": True,
        "reason": "parent_replay_input_unavailable",
    }
    assert summary["degraded"] is True
    assert summary["errors"] == 1
    assert summary["skipped"] == "parent_replay_input_unavailable"
    assert summary["clean_checked"] == 0


class _HostileBool:
    def __bool__(self):  # pragma: no cover - exercised by boundary code
        raise RuntimeError("hostile bool conversion")


def test_stage1413_parent_replay_replayed_marker_does_not_truthiness_crash():
    result = {
        "_umige_parent_model_replayed": _HostileBool(),
        "file": "sample.py",
        "classification": "benign",
        "score": 1.0,
        "tags": ["normal_tag"],
        "engine_context": {"other": 1.0},
    }

    summary = parent_replay_result_learning(result)

    assert summary["errors"] >= 0
    assert result["_umige_parent_model_replayed"] is True
