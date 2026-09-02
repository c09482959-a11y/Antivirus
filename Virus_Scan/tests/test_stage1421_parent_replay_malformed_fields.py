"""Stage 1421: parent replay malformed model fields must not learn as empty defaults."""

from pathlib import Path

from Virus_Scan.models.replay.transaction_projection import project_runtime_transaction_stats
from Virus_Scan.models.replay.api import parent_replay_result_learning, result_learning_payload
from Virus_Scan.tests.support.profile_learning import (
    accepted_learning_request,
    accepted_runtime_transaction_result,
)


class _HostileBool:
    def __bool__(self):  # pragma: no cover - exercised by boundary code
        raise RuntimeError("hostile bool conversion")


class _UnsupportedSequence:
    def __iter__(self):  # pragma: no cover - should not be trusted as a model sequence
        yield "normal_tag"


class _UnsupportedMapping:
    def keys(self):  # pragma: no cover - should not be trusted as a replay mapping
        return ("allow_learning",)


def _base_result():
    return {
        "file": "sample.py",
        "classification": "benign",
        "score": 1.0,
        "engine_context": {"other": 1.0},
        "scan_integrity": {"allow_learning": True},
    }


def _payload_with(**updates):
    result = _base_result()
    result.update(updates)
    return result


def test_stage1421_parent_replay_malformed_tags_do_not_become_empty_learned_flow():
    result = _payload_with(tags=_UnsupportedSequence())

    payload = result_learning_payload(result)
    summary = parent_replay_result_learning(result)

    assert payload == {
        "replay_payload_unavailable": True,
        "reason": "parent_replay_input_unavailable",
    }
    assert summary["degraded"] is True
    assert summary["errors"] == 1
    assert summary["clean_checked"] == 0
    assert summary["committed"] == 0
    assert summary["runtime"] == 0


def test_stage1421_parent_replay_malformed_yara_hits_do_not_become_empty_evidence():
    result = _payload_with(tags=["normal_tag"], yara_hits=_UnsupportedSequence())

    payload = result_learning_payload(result)
    summary = parent_replay_result_learning(result)

    assert payload == {
        "replay_payload_unavailable": True,
        "reason": "parent_replay_input_unavailable",
    }
    assert summary["degraded"] is True
    assert summary["clean_checked"] == 0
    assert summary["committed"] == 0


def test_stage1421_parent_replay_malformed_scan_integrity_blocks_learning():
    result = _payload_with(tags=["normal_tag"], scan_integrity=_UnsupportedMapping())

    payload = result_learning_payload(result)
    summary = parent_replay_result_learning(result)

    assert payload == {
        "replay_payload_unavailable": True,
        "reason": "parent_replay_input_unavailable",
    }
    assert summary["degraded"] is True
    assert summary["errors"] == 1
    assert summary["committed"] == 0


def test_stage1421_parent_replay_hostile_truthiness_field_does_not_crash_or_learn():
    result = _payload_with(tags=_HostileBool())

    payload = result_learning_payload(result)
    summary = parent_replay_result_learning(result)

    assert payload == {
        "replay_payload_unavailable": True,
        "reason": "parent_replay_input_unavailable",
    }
    assert summary["degraded"] is True
    assert summary["committed"] == 0


def test_stage1421_runtime_transaction_projection_malformed_status_fails_closed(
    tmp_path: Path,
):
    sample = tmp_path / "sample.py"
    sample.write_text("pass\n", encoding="utf-8")
    request = accepted_learning_request(sample, flow=("decode", "execute"))
    learning_result = accepted_runtime_transaction_result(request)
    learning_result["target_status"] = _HostileBool()

    summary = {"runtime": 0}
    stats = project_runtime_transaction_stats(learning_result, summary)

    assert stats["runtime_committed"] is False
    assert stats["reason"] == "runtime_target_status_unavailable"
    assert stats["model_updates_authorized"] is True
    assert summary["runtime"] == 0
