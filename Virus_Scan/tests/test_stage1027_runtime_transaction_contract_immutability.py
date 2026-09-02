from __future__ import annotations

import pytest

from Virus_Scan.runtime.transactional_state import RuntimeTransaction


def test_stage1027_runtime_transaction_direct_constructor_deep_freezes_transitions() -> None:
    payload = {"state": ["queued"]}
    transition_record = {"owner": "queue", "action": "set", "key": "job:a", "value": payload}
    caller_transitions = [transition_record]

    tx = RuntimeTransaction(transaction_id=123, owner="queue", transitions=caller_transitions, parent=None, reason=None)  # type: ignore[arg-type]

    payload["state"].append("mutated")
    transition_record["value"] = {"state": ["replaced"]}
    caller_transitions.append({"owner": "queue", "action": "set", "key": "job:b", "value": "new"})

    assert tx.transaction_id == "123"
    assert tx.owner == "queue"
    assert tx.parent == ""
    assert tx.reason == ""
    assert len(tx.transitions) == 1
    assert tx.transitions[0].canonical()["value"] == {"state": ["queued"]}
    with pytest.raises(AttributeError):
        tx.transitions = ()  # type: ignore[misc]


def test_stage1027_runtime_transaction_direct_constructor_rejects_cross_owner_transition() -> None:
    with pytest.raises(PermissionError, match="cannot contain transition"):
        RuntimeTransaction(
            transaction_id="tx",
            owner="queue",
            transitions=({"owner": "scanner", "action": "set", "key": "job:a", "value": "bad"},),  # type: ignore[arg-type]
        )
