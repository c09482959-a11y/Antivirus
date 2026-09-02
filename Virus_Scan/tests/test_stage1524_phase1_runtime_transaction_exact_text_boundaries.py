from __future__ import annotations

from Virus_Scan.runtime.immutable_core import RuntimeTransition, materialize_runtime_value
from Virus_Scan.runtime.transactional_state import RuntimeTransaction, TransactionalRuntimeJournal


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.str_calls = 0
        obj.bool_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves caller-owned __str__ was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def __bool__(self):  # pragma: no cover - failure proves caller-owned bool was used
        self.bool_calls += 1
        raise AssertionError("caller-owned bool was invoked")


def h(value: str) -> HostileText:
    return HostileText(value)


def assert_no_hooks(*values: HostileText) -> None:
    for value in values:
        assert value.str_calls == 0
        assert value.bool_calls == 0


def test_stage1524_runtime_transition_detaches_exact_text_fields_and_values() -> None:
    owner = h("queue")
    action = h("set")
    key = h("job:a")
    parent = h("parent")
    reason = h("checkpoint")
    value_key = h("state")
    value_text = h("queued")

    transition = RuntimeTransition(
        owner=owner,
        action=action,
        key=key,
        value={value_key: value_text},
        parent=parent,
        reason=reason,
    )

    assert transition.owner == "queue"
    assert transition.action == "set"
    assert transition.key == "job:a"
    assert transition.parent == "parent"
    assert transition.reason == "checkpoint"
    assert transition.canonical()["value"] == {"state": "queued"}
    materialized = materialize_runtime_value(transition.value)
    assert materialized == {"state": "queued"}
    assert type(materialized["state"]) is str
    assert_no_hooks(owner, action, key, parent, reason, value_key, value_text)


def test_stage1524_runtime_transaction_and_journal_do_not_probe_text_truthiness() -> None:
    owner = h("queue")
    reason = h("apply")
    transition = RuntimeTransition(owner=owner, action=h("set"), key=h("job:b"), value=h("done"))

    tx = RuntimeTransaction.build(owner=owner, transitions=(transition,), reason=reason)
    journal = TransactionalRuntimeJournal(owner=owner)
    checkpoint = journal.apply(tx)

    assert tx.owner == "queue"
    assert tx.reason == "apply"
    assert checkpoint.canonical()["values"] == {"job:b": "done"}
    assert checkpoint.owner == "queue"
    assert_no_hooks(owner, reason)
