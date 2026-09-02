from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.retire_tokens import consume_queue_worker_retire, request_queue_worker_retire
from Virus_Scan.scheduler.workers.retire_tokens_evidence import (
    retire_token_consume_decision,
    retire_token_name_decision,
    retire_token_request_decision,
)


class HostileTokenName:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise AssertionError("str hook executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("repr hook executed")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("format hook executed")



def test_stage2154_retire_token_name_rejection_is_replayable_without_hooks() -> None:
    HostileTokenName.reset()

    decision = retire_token_name_decision(HostileTokenName())

    assert HostileTokenName.touched == 0
    assert decision.name == ""
    assert decision.accepted is False
    assert decision.reason == "queue_retire_token_name_rejected"
    assert ("decision", "retire_token_name") in decision.evidence
    assert ("value_type", "HostileTokenName") in decision.evidence



def test_stage2154_retire_token_request_zero_count_is_typed_replayable() -> None:
    decision = retire_token_request_decision(0, reason="")

    assert decision.requested == 0
    assert decision.accepted is False
    assert decision.reason == "queue_worker_retire_count_zero"
    assert ("decision", "retire_token_request") in decision.evidence
    assert ("requested", 0) in decision.evidence



def test_stage2154_retire_token_consume_unavailable_is_typed_replayable() -> None:
    decision = retire_token_consume_decision(False, reason="queue_retire_token_unavailable")

    assert decision.consumed is False
    assert decision.accepted is True
    assert decision.reason == "queue_retire_token_unavailable"
    assert ("decision", "retire_token_consume") in decision.evidence



def test_stage2154_retire_tokens_preserve_public_count_and_consume_behavior(tmp_path) -> None:
    assert request_queue_worker_retire(tmp_path, 0) == 0
    assert request_queue_worker_retire(tmp_path, 2) == 2
    assert consume_queue_worker_retire(tmp_path) is True
    assert consume_queue_worker_retire(tmp_path) is True
    assert consume_queue_worker_retire(tmp_path) is False



def test_stage2154_retire_tokens_source_removed_hidden_scalar_sentinels() -> None:
    source = (Path(__file__).resolve().parents[1] / "scheduler" / "workers" / "retire_tokens.py").read_text(encoding="utf-8")
    assert "return ''" not in source
    assert 'return ""' not in source
    assert "return 0" not in source
    assert "return False" not in source
