"""Stage2164 scheduler replay projection decision tests."""
from __future__ import annotations

from Virus_Scan.scheduler.replay.replay_projection import (
    canonical_replay_sequence,
    canonical_replay_sequence_decision,
    replay_evidence_key_text,
    replay_evidence_key_text_decision,
)
from Virus_Scan.scheduler.replay import replay_projection_failure
from Virus_Scan.scheduler.replay.replay_projection_failure import build_replay_projection_failure_result


class HostileReplayKey:
    str_calls = 0
    repr_calls = 0
    bool_calls = 0

    def __str__(self) -> str:
        type(self).str_calls += 1
        raise RuntimeError("str hook called")

    def __repr__(self) -> str:
        type(self).repr_calls += 1
        raise RuntimeError("repr hook called")

    def __bool__(self) -> bool:
        type(self).bool_calls += 1
        raise RuntimeError("bool hook called")


def _reset_hostile_key() -> None:
    HostileReplayKey.str_calls = 0
    HostileReplayKey.repr_calls = 0
    HostileReplayKey.bool_calls = 0


def test_stage2164_replay_sequence_none_has_replayable_decision() -> None:
    decision = canonical_replay_sequence_decision(None)

    assert decision.sequence == ()
    assert decision.accepted is False
    assert decision.reason == "missing_replay_sequence"
    assert decision.source_type == "NoneType"
    assert canonical_replay_sequence(None) == decision.sequence


def test_stage2164_replay_evidence_key_rejects_unsupported_key_without_blank_collapse() -> None:
    _reset_hostile_key()
    key = HostileReplayKey()

    decision = replay_evidence_key_text_decision(key)

    assert decision.accepted is False
    assert decision.reason == "unsupported_replay_evidence_key"
    assert decision.text == "unsupported_replay_evidence_key:HostileReplayKey"
    assert replay_evidence_key_text(key) == decision.text
    assert HostileReplayKey.str_calls == 0
    assert HostileReplayKey.repr_calls == 0
    assert HostileReplayKey.bool_calls == 0


def test_stage2164_projection_failure_records_missing_raw_results() -> None:
    decision = replay_projection_failure._raw_replay_records_decision(None)

    assert decision.accepted is False
    assert decision.reason == "missing_replay_raw_records"
    assert decision.source_type == "NoneType"
    assert decision.records == ({
        "record_index": 0,
        "missing_replay_raw_records": True,
        "replay_raw_records_unavailable_reason": "missing_replay_raw_records",
    },)

    result = build_replay_projection_failure_result("actual", RuntimeError("boom"), None)
    assert result.actual.records == decision.records
    assert result.actual.evidence[0]["replay_must_record"] is True
