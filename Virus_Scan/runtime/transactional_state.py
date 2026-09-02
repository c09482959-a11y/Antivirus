"""Transactional runtime state primitives for replay-sensitive orchestration.

Stage109 real remediation: this module provides an owned transaction journal on
 top of immutable transition records.  It is deliberately independent from
 scheduler objects so existing scan/scoring behavior is preserved while
 new recovery paths can prove rollback, replay hashing, and checkpoint integrity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Iterable
import hashlib
import json
import threading

from Virus_Scan.contracts.no_hook_materialization import (
    exact_int_or_none,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.immutable_core import RuntimeTransition, RuntimeStateReducer, freeze_runtime_value, materialize_runtime_value
from Virus_Scan.runtime.provenance import stable_digest, append_provenance_event


def _transaction_text(value: object, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="runtime_transaction_text_missing",
        unsupported_reason="runtime_transaction_text_rejected",
    )
    if reason:
        return default
    return text if text != "" else default


def _transaction_int(value: object, default: int) -> int:
    parsed = exact_int_or_none(value)
    return default if parsed is None else parsed


def _safe(value: object) -> object:
    return materialize_runtime_value(freeze_runtime_value(value))


def _transaction_owner_permission_message(owner: str, transition_owner: str) -> str:
    return (
        "transaction owner "
        + repr(owner)
        + " cannot contain transition for "
        + repr(transition_owner)
    )


def _transition_from_value(value: object, owner: str) -> RuntimeTransition:
    if type(value) is RuntimeTransition:
        return value
    items = no_hook_mapping_items(value)
    if items is None:
        return RuntimeTransition(
            owner=owner,
            action="set",
            key="",
            value={
                "value": None,
                "unavailable_reason": "runtime_transaction_transition_rejected",
            },
        )
    fields = {
        str.__str__(key): item
        for key, item in items
        if type(key) is str
    }
    return RuntimeTransition(**fields)


def _transition_values(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if type(value) in (tuple, list):
        return no_hook_sequence_items(value)
    return ()


def _digest(payload: object) -> str:
    try:
        data = json.dumps(_safe(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except RECOVERABLE_RUNTIME_ERRORS:
        data = _transaction_text(_safe(payload))
    return hashlib.sha256(data.encode("utf-8", "replace")).hexdigest()[:32]


@dataclass(frozen=True)
class RuntimeTransaction:
    transaction_id: str
    owner: str
    transitions: tuple[RuntimeTransition, ...]
    parent: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if type(self) is not RuntimeTransaction:
            exception_message = "runtime transaction owner rejected"
            raise TypeError(exception_message)
        owner = _transaction_text(self.owner, "runtime")
        normalized: list[RuntimeTransition] = []
        for item in _transition_values(self.transitions):
            tr = _transition_from_value(item, owner)
            transition_owner = _transaction_text(tr.owner, owner)
            if transition_owner != owner:
                raise PermissionError(_transaction_owner_permission_message(owner, transition_owner))
            normalized.append(tr)
        object.__setattr__(self, "transaction_id", _transaction_text(self.transaction_id, ""))
        object.__setattr__(self, "owner", owner)
        object.__setattr__(self, "transitions", tuple(normalized))
        object.__setattr__(self, "parent", _transaction_text(self.parent, ""))
        object.__setattr__(self, "reason", _transaction_text(self.reason, ""))

    @classmethod
    def build(cls, *, owner: str, transitions: Iterable[RuntimeTransition | Mapping[str, object]], parent: str = "", reason: str = "") -> "RuntimeTransaction":
        normalized_owner = _transaction_text(owner, "runtime")
        normalized_parent = _transaction_text(parent, "")
        normalized_reason = _transaction_text(reason, "")
        normalized: list[RuntimeTransition] = []
        for item in _transition_values(transitions):
            tr = _transition_from_value(item, normalized_owner)
            transition_owner = _transaction_text(tr.owner, normalized_owner)
            if transition_owner != normalized_owner:
                raise PermissionError(_transaction_owner_permission_message(normalized_owner, transition_owner))
            normalized.append(tr)
        tx_id = stable_digest("runtime_transaction", normalized_owner, [t.canonical() for t in normalized], normalized_parent, normalized_reason)
        return cls(transaction_id=tx_id, owner=normalized_owner, transitions=tuple(normalized), parent=normalized_parent, reason=normalized_reason)

    def canonical(self) -> dict[str, object]:
        return {
            "transaction_id": self.transaction_id,
            "owner": self.owner,
            "parent": self.parent,
            "reason": self.reason,
            "transitions": [t.canonical() for t in self.transitions],
        }


@dataclass(frozen=True)
class RuntimeCheckpoint:
    owner: str
    version: int
    digest: str
    values: Mapping[str, object] = field(default_factory=dict)
    journal_digest: str = ""

    def __post_init__(self) -> None:
        if type(self) is not RuntimeCheckpoint:
            exception_message = "runtime checkpoint owner rejected"
            raise TypeError(exception_message)
        object.__setattr__(self, "values", freeze_runtime_value({} if self.values is None else self.values))

    def canonical(self) -> dict[str, object]:
        return {"owner": _transaction_text(self.owner, "runtime"), "version": _transaction_int(self.version, 0), "digest": _transaction_text(self.digest, ""), "values": _safe(materialize_runtime_value(self.values)), "journal_digest": _transaction_text(self.journal_digest, "")}


class TransactionalRuntimeJournal:
    """Owned append-only transaction journal with deterministic replay hashing."""

    def __init__(self, *, owner: str, max_transactions: int = 4096) -> None:
        self.owner = _transaction_text(owner, "runtime")
        self.max_transactions = max(1, _transaction_int(max_transactions, 4096))
        self._lock = threading.RLock()
        self._reducer = RuntimeStateReducer(owner=self.owner, max_history=self.max_transactions * 4)
        self._journal: list[dict[str, object]] = []

    def apply(self, tx: RuntimeTransaction | Mapping[str, object]) -> RuntimeCheckpoint:
        if type(tx) is not RuntimeTransaction:
            items = no_hook_mapping_items(tx)
            if items is None:
                exception_message = "runtime transaction mapping rejected"
                raise TypeError(exception_message)
            data = dict(items)
            raw_transitions = dict.get(data, "transitions")
            tx = RuntimeTransaction.build(
                owner=_transaction_text(dict.get(data, "owner"), self.owner),
                transitions=raw_transitions if raw_transitions is not None else (),
                parent=_transaction_text(dict.get(data, "parent"), ""),
                reason=_transaction_text(dict.get(data, "reason"), ""),
            )
        if tx.owner != self.owner:
            raise PermissionError(
                "journal owner mismatch: "
                + repr(_transaction_text(tx.owner, "runtime"))
                + " cannot mutate "
                + repr(self.owner)
            )
        with self._lock:
            before = self.checkpoint()
            try:
                for transition in tx.transitions:
                    self._reducer.apply(transition)
                after_state = self._reducer.current()
                record = {"event_type": "runtime_transaction", "transaction": tx.canonical(), "before": before.canonical(), "after_digest": after_state.digest, "after_version": after_state.version}
                self._journal.append(record)
                if len(self._journal) > self.max_transactions:
                    del self._journal[: len(self._journal) - self.max_transactions]
                append_provenance_event(record)
                return self.checkpoint()
            except RECOVERABLE_RUNTIME_ERRORS as exc:
                append_provenance_event({"event_type": "runtime_transaction_failed", "owner": self.owner, "transaction": tx.canonical(), "before": before.canonical(), "error": _transaction_text(exc)[:500]})
                raise

    def checkpoint(self) -> RuntimeCheckpoint:
        state = self._reducer.current()
        journal_digest = _digest([r.get("transaction", {}) for r in self._journal])
        return RuntimeCheckpoint(owner=self.owner, version=state.version, digest=state.digest, values=state.snapshot(), journal_digest=journal_digest)

    def journal_snapshot(self) -> tuple[dict[str, object], ...]:
        with self._lock:
            return tuple(_safe(r) for r in self._journal)

    def replay_hash(self) -> str:
        with self._lock:
            return _digest({"owner": self.owner, "checkpoint": self.checkpoint().canonical(), "journal": list(self._journal)})

    @staticmethod
    def replay(owner: str, journal: Iterable[Mapping[str, object]]) -> RuntimeCheckpoint:
        rebuilt = TransactionalRuntimeJournal(owner=owner)
        records = no_hook_sequence_items(journal) if type(journal) in (tuple, list) else ()
        for record in records:
            items = no_hook_mapping_items(record)
            data = dict(items) if items is not None else {}
            tx = dict.get(data, "transaction")
            tx_items = no_hook_mapping_items(tx)
            if tx_items is not None:
                rebuilt.apply(dict(tx_items))
        return rebuilt.checkpoint()


__all__ = ("RuntimeCheckpoint", "RuntimeTransaction", "TransactionalRuntimeJournal")
