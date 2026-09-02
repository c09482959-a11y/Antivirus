"""Canonical persisted learning-transaction state contract."""
from __future__ import annotations

from typing import Final

from Virus_Scan.models.contracts.learning_authority import LearningDecision
from Virus_Scan.models.profiles.schema_versions import (
    PROFILE_LEARNING_TRANSACTION_SCHEMA_VERSION,
)

TRANSACTION_TARGET_ORDER: Final[tuple[str, ...]] = (
    "profile", "markov", "temporal", "filetype", "clustering",
)
TRANSACTION_TARGET_STATUSES: Final[frozenset[str]] = frozenset({
    "pending", "in_progress", "succeeded", "failed",
})
PROFILE_TRANSACTION_STORE_LIMIT: Final[int] = 1024


def _nonnegative_int(value: object) -> bool:
    return type(value) is int and not isinstance(value, bool) and value >= 0


def authorized_transaction_target_order(
    decision: LearningDecision,
) -> tuple[str, ...]:
    """Return the canonical ordered target subset authorized by a decision."""
    if type(decision) is not LearningDecision:
        raise ValueError("learning transaction decision invalid")
    return tuple(
        target for target in TRANSACTION_TARGET_ORDER
        if decision.authorizes(target)
    )


def validate_transaction_targets(
    order: object, targets: object,
) -> tuple[str, ...]:
    """Validate exact target membership; mapping insertion order is non-semantic."""
    if type(order) is not list or type(targets) is not dict:
        raise ValueError("learning transaction targets invalid")
    if any(type(target) is not str or target == "" for target in order):
        raise ValueError("learning transaction target order invalid")
    ordered = tuple(order)
    target_set = frozenset(ordered)
    if len(ordered) != len(target_set):
        raise ValueError("learning transaction target order invalid")
    canonical = tuple(
        target for target in TRANSACTION_TARGET_ORDER if target in target_set
    )
    if ordered != canonical:
        raise ValueError("learning transaction target order invalid")
    if len(targets) != len(ordered) or frozenset(targets) != target_set:
        raise ValueError("learning transaction targets invalid")
    for target in ordered:
        state = targets.get(target)
        if type(state) is not dict:
            raise ValueError("learning transaction target record invalid")
        status = state.get("status")
        attempts = state.get("attempts")
        reason = state.get("reason")
        output = state.get("output")
        if status not in TRANSACTION_TARGET_STATUSES:
            raise ValueError("learning transaction target status invalid")
        if not _nonnegative_int(attempts):
            raise ValueError("learning transaction target attempts invalid")
        if type(reason) is not str or type(output) is not dict:
            raise ValueError("learning transaction target evidence invalid")
        if status == "pending" and (attempts != 0 or reason or output):
            raise ValueError("learning transaction pending target invalid")
        if status == "in_progress" and (attempts < 1 or reason or output):
            raise ValueError("learning transaction active target invalid")
        if status == "succeeded" and (attempts < 1 or reason):
            raise ValueError("learning transaction succeeded target invalid")
        if status == "failed" and (attempts < 1 or reason == ""):
            raise ValueError("learning transaction failed target invalid")
    return ordered


def refresh_transaction_status(transaction: dict[str, object]) -> None:
    """Publish counters and aggregate status from exact per-target state."""
    ordered = validate_transaction_targets(
        transaction.get("target_order"), transaction.get("targets"),
    )
    targets = transaction["targets"]
    assert type(targets) is dict
    states = tuple(targets[target] for target in ordered)
    completed = sum(state["status"] == "succeeded" for state in states)
    failed = sum(state["status"] == "failed" for state in states)
    transaction["completed_targets"] = completed
    transaction["failed_targets"] = failed
    transaction["status"] = (
        "complete" if states and completed == len(states)
        else "partial" if failed else "pending"
    )



def validate_transaction_store(value: object) -> bool:
    """Validate the bounded persisted transaction registry."""
    if type(value) is not dict or len(value) > PROFILE_TRANSACTION_STORE_LIMIT:
        raise ValueError("learning_transactions must be a bounded object")
    for replay_key, transaction in value.items():
        validate_persisted_transaction(replay_key, transaction)
    return True


def prune_completed_transactions(store: dict[str, object]) -> None:
    """Retain every recoverable transaction and newest completed records."""
    if type(store) is not dict:
        raise ValueError("learning_transactions must be an object")
    if len(store) <= PROFILE_TRANSACTION_STORE_LIMIT:
        return
    incomplete: list[tuple[int, str]] = []
    complete: list[tuple[int, str]] = []
    for replay_key, transaction in store.items():
        decision = validate_persisted_transaction(replay_key, transaction)
        record = (decision.decision_ordinal, replay_key)
        if transaction["status"] == "complete":
            complete.append(record)
        else:
            incomplete.append(record)
    if len(incomplete) > PROFILE_TRANSACTION_STORE_LIMIT:
        raise ValueError("too many recoverable learning transactions")
    slots = PROFILE_TRANSACTION_STORE_LIMIT - len(incomplete)
    keep = {key for _ordinal, key in incomplete}
    keep.update(
        key for _ordinal, key in sorted(complete, reverse=True)[:slots]
    )
    for replay_key in tuple(store):
        if replay_key not in keep:
            store.pop(replay_key, None)


def validate_persisted_transaction(
    replay_key: object, transaction: object,
) -> LearningDecision:
    """Validate one complete persisted transaction and return its decision."""
    if type(replay_key) is not str or type(transaction) is not dict:
        raise ValueError("learning transaction record invalid")
    if transaction.get("schema_version") != PROFILE_LEARNING_TRANSACTION_SCHEMA_VERSION:
        raise ValueError("learning transaction schema invalid")
    if transaction.get("replay_key") != replay_key:
        raise ValueError("learning transaction identity invalid")
    try:
        decision = LearningDecision.from_record(transaction.get("decision"))
    except ValueError as exc:
        raise ValueError("learning transaction decision invalid") from exc
    if (
        decision.replay_key != replay_key
        or transaction.get("observation_id") != decision.observation_id
        or transaction.get("observation_digest") != decision.observation_digest
        or transaction.get("decision_ordinal") != decision.decision_ordinal
    ):
        raise ValueError("learning transaction decision mismatch")
    if type(transaction.get("context_key")) is not str or not transaction["context_key"]:
        raise ValueError("learning transaction context invalid")
    if type(transaction.get("diversity_key")) is not str or not transaction["diversity_key"]:
        raise ValueError("learning transaction diversity invalid")
    expected_order = list(authorized_transaction_target_order(decision))
    if transaction.get("target_order") != expected_order:
        raise ValueError("learning transaction target order invalid")
    ordered = validate_transaction_targets(expected_order, transaction.get("targets"))
    targets = transaction["targets"]
    assert type(targets) is dict
    states = tuple(targets[target] for target in ordered)
    completed = sum(state["status"] == "succeeded" for state in states)
    failed = sum(state["status"] == "failed" for state in states)
    expected_status = (
        "complete" if states and completed == len(states)
        else "partial" if failed else "pending"
    )
    authoritative_transaction_id = transaction.get(
        "authoritative_transaction_id",
    )
    if expected_status == "complete":
        if (
            type(authoritative_transaction_id) is not str
            or len(authoritative_transaction_id) != 64
            or any(
                character not in "0123456789abcdef"
                for character in authoritative_transaction_id
            )
        ):
            raise ValueError("learning transaction authority identity invalid")
    elif authoritative_transaction_id not in (None, ""):
        raise ValueError("learning transaction authority identity premature")
    if (
        transaction.get("completed_targets") != completed
        or transaction.get("failed_targets") != failed
        or transaction.get("status") != expected_status
    ):
        raise ValueError("learning transaction aggregate state invalid")
    return decision


__all__ = (
    "PROFILE_TRANSACTION_STORE_LIMIT",
    "TRANSACTION_TARGET_ORDER",
    "TRANSACTION_TARGET_STATUSES",
    "authorized_transaction_target_order",
    "prune_completed_transactions",
    "refresh_transaction_status",
    "validate_persisted_transaction",
    "validate_transaction_store",
    "validate_transaction_targets",
)
