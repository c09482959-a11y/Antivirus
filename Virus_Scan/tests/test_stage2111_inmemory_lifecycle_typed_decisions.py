from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.queue.inmemory_lifecycle_decisions import mark_retry_admitted_decision, terminal_transition_decision
from Virus_Scan.scheduler.queue.inmemory_lifecycle import InMemoryLifecycleMutationDecision


def test_stage2111_retry_admission_rejections_are_typed_replayable_decisions() -> None:
    decision = mark_retry_admitted_decision([], attempt=1, now=10.0)  # type: ignore[arg-type]

    assert isinstance(decision, InMemoryLifecycleMutationDecision)
    assert decision.accepted is False
    assert decision.reason == "lifecycle_record_rejected"
    assert decision.field == "record"
    assert decision.transition == "retry_admitted"
    assert decision.changed is False


def test_stage2111_retry_admission_mismatch_has_explicit_reason() -> None:
    record = {"attempt": 2, "state": "pending_retry", "retry_pending_active": True, "history": ()}

    decision = mark_retry_admitted_decision(record, attempt=1, now=20.0)

    assert decision.accepted is False
    assert decision.reason == "lifecycle_generation_mismatch"
    assert decision.field == "attempt"
    assert decision.transition == "retry_admitted"
    assert record["retry_pending_active"] is True


def test_stage2111_retry_admission_success_records_changed_decision() -> None:
    record = {"attempt": 3, "state": "pending_retry", "retry_pending_active": True, "history": ()}

    decision = mark_retry_admitted_decision(record, attempt=3, now=30.0)

    assert decision.accepted is True
    assert decision.reason == "retry_generation_admitted"
    assert decision.changed is True
    assert record["retry_pending_active"] is False
    assert record["retry_admitted_generation"] == 3


def test_stage2111_terminal_transition_rejections_are_typed_replayable_decisions() -> None:
    record = {"attempt": 5, "state": "running", "retry_pending_active": True}

    mismatch = terminal_transition_decision(record, state="done", attempt=4, now=40.0)
    assert mismatch.accepted is False
    assert mismatch.reason == "lifecycle_generation_mismatch"
    assert mismatch.field == "attempt"
    assert mismatch.transition == "terminal_transition"

    rejected_record = terminal_transition_decision([], state="done", attempt=4, now=40.0)  # type: ignore[arg-type]
    assert rejected_record.accepted is False
    assert rejected_record.reason == "lifecycle_record_rejected"
    assert rejected_record.field == "record"


def test_stage2111_terminal_transition_success_records_changed_decision() -> None:
    record = {"attempt": 6, "state": "running", "retry_pending_active": True}

    decision = terminal_transition_decision(record, state="done", attempt=6, now=60.0)

    assert decision.accepted is True
    assert decision.reason == "terminal_transition_applied"
    assert decision.changed is True
    assert record["state"] == "done"
    assert record["terminal_time"] == 60.0


def test_stage2111_old_hidden_lifecycle_literal_returns_are_removed_from_source() -> None:
    lifecycle_source = Path("Virus_Scan/scheduler/queue/inmemory_lifecycle.py").read_text(encoding="utf-8")
    decision_source = Path("Virus_Scan/scheduler/queue/inmemory_lifecycle_decisions.py").read_text(encoding="utf-8")
    source = lifecycle_source + "\n" + decision_source
    tree = ast.parse(source)
    target_functions = {
        "mark_retry_admitted_decision",
        "terminal_transition_decision",
        "_record_rejections",
    }
    forbidden_wrapper_snippets = (
        "def mark_retry_admitted(",
        "def transition_generation_is_current(",
        "def terminal_transition(",
        '"mark_retry_admitted"',
        '"transition_generation_is_current"',
        '"terminal_transition"',
        "Compatibility boolean",
    )
    for snippet in forbidden_wrapper_snippets:
        assert snippet not in lifecycle_source
    forbidden_returns: list[tuple[str, int, object]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in target_functions:
            for child in ast.walk(node):
                if isinstance(child, ast.Return):
                    if child.value is None:
                        forbidden_returns.append((node.name, child.lineno, None))
                    elif isinstance(child.value, ast.Constant) and child.value.value in (False, None):
                        forbidden_returns.append((node.name, child.lineno, child.value.value))
    assert forbidden_returns == []
