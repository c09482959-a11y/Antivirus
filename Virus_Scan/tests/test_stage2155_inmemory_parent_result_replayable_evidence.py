from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from pathlib import Path

from Virus_Scan.scheduler.orchestration.inmemory_parent_result import (
    _is_parent_result_message,
    handle_next_inmemory_parent_result,
)
from Virus_Scan.scheduler.orchestration.inmemory_parent_result_evidence import (
    parent_result_continue_decision,
    parent_result_message_decision,
)
from Virus_Scan.tests.test_stage1862_scheduler_inmemory_parent_result_no_hook import EmptyQueue, HostileList, HostileMessage, _handle_with_message


class ContinueMessageQueue:
    def get(self, *, timeout):  # noqa: ARG002 - queue-compatible test double
        return ["unknown-kind"]


def _handle_unknown_message() -> bool:
    return handle_next_inmemory_parent_result(
        result_queue=ContinueMessageQueue(),
        job_records={},
        active={},
        terminal=set(),
        failed=set(),
        done=set(),
        results={},
        recovery=None,
        state_index=InMemorySchedulerStateIndex(),
        root=".",
        routing_evidence_context={},
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_flags={},
        partial_output_path=None,
        partial_output_every=10,
        started_at=0.0,
        progress_every=10,
        throttle_sec=0.0,
        result_retainer=lambda _path, result: result,
        derived_cache_writer=lambda _result: False,
        recoverable_exceptions=(Exception,),
    )


def test_stage2155_parent_result_message_rejection_is_replayable_without_hooks() -> None:
    HostileMessage.touched = False

    decision = parent_result_message_decision(HostileMessage())

    assert HostileMessage.touched is False
    assert decision.is_parent_result is False
    assert decision.accepted is False
    assert decision.reason == "parent_result_message_type_rejected"
    assert ("decision", "parent_result_message") in decision.evidence
    assert ("reason", "parent_result_message_type_rejected") in decision.evidence


def test_stage2155_parent_result_exact_empty_sequence_is_distinguished_from_valid_message() -> None:
    empty = parent_result_message_decision([])
    accepted = parent_result_message_decision(["done"])

    assert empty.is_parent_result is False
    assert empty.reason == "parent_result_message_empty"
    assert ("item_count", 0) in empty.evidence
    assert accepted.is_parent_result is True
    assert accepted.accepted is True
    assert accepted.reason == "accepted_parent_result_message"


def test_stage2155_parent_result_continue_false_projection_is_typed() -> None:
    decision = parent_result_continue_decision(
        should_continue=False,
        accepted=True,
        reason="parent_result_queue_empty",
    )

    assert decision.should_continue is False
    assert decision.accepted is True
    assert decision.reason == "parent_result_queue_empty"
    assert ("decision", "parent_result_continue") in decision.evidence


def test_stage2155_public_parent_result_behavior_is_preserved() -> None:
    assert _is_parent_result_message(["done"]) is True
    assert _is_parent_result_message(()) is False
    assert _handle_with_message(HostileMessage()) is False
    assert _handle_with_message(HostileList(["done"])) is False
    assert _handle_unknown_message() is False
    assert handle_next_inmemory_parent_result(
        result_queue=EmptyQueue(),
        job_records={},
        active={},
        terminal=set(),
        failed=set(),
        done=set(),
        results={},
        recovery=None,
        state_index=InMemorySchedulerStateIndex(),
        root=".",
        routing_evidence_context={},
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_flags={},
        partial_output_path=None,
        partial_output_every=10,
        started_at=0.0,
        progress_every=10,
        throttle_sec=0.0,
        result_retainer=lambda _path, result: result,
        derived_cache_writer=lambda _result: False,
        recoverable_exceptions=(Exception,),
    ) is False


def test_stage2155_inmemory_parent_result_source_removed_hidden_false_returns() -> None:
    source = (Path(__file__).resolve().parents[1] / "scheduler" / "orchestration" / "inmemory_parent_result.py").read_text(
        encoding="utf-8"
    )

    assert "return False" not in source
    assert "parent_result_message_decision" in source
    assert "parent_result_continue_decision" in source
