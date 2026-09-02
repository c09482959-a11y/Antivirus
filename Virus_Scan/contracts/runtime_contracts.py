"""Formal runtime ownership contracts for scheduler/replay boundaries."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
import hashlib
import json
import threading

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_json_sort_key,
    no_hook_materialize,
    no_hook_mapping_items,
    no_hook_text,
)

_CONTRACT_DIGEST_JSON_ERRORS = (TypeError, ValueError, OverflowError, RecursionError, UnicodeError, RuntimeError)


def _contract_text(value: object, default: str, *, reason: str = "unsafe_runtime_contract_text_rejected") -> str:
    text, text_reason = no_hook_text(value, missing_reason="missing_runtime_contract_text", unsupported_reason=reason)
    if text_reason:
        return default
    return text


def _contract_int(value: object, default: int = 0) -> int:
    if type(value) is bool:
        return int(default)
    if type(value) is int:
        return value
    text, reason = no_hook_text(value, unsupported_reason="unsafe_runtime_contract_number_rejected")
    if reason:
        return int(default)
    try:
        return int(str.__str__(text).strip())
    except (TypeError, ValueError, OverflowError):
        return int(default)


def _contract_json_safe(value: object) -> object:
    return no_hook_materialize(value, reason_prefix="runtime_contract")


def _contract_stable_digest(*parts: object) -> str:
    payload_value = [_contract_json_safe(part) for part in parts]
    try:
        payload = json.dumps(payload_value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except _CONTRACT_DIGEST_JSON_ERRORS:
        payload = json.dumps(
            [no_hook_json_sort_key(part) for part in payload_value],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:24]


@dataclass(frozen=True)
class QueueOwnershipContract:
    queue_id: str
    owner_domain: str
    scheduler_id: str = "scheduler"
    replay_id: str = ""
    generation: int = 0

    def canonical(self) -> dict[str, object]:
        return {
            "queue_id": _contract_text(self.queue_id, ""),
            "owner_domain": _contract_text(self.owner_domain, "scheduler"),
            "scheduler_id": _contract_text(self.scheduler_id, "scheduler"),
            "replay_id": _contract_text(self.replay_id, ""),
            "generation": _contract_int(self.generation, 0),
        }

    @property
    def contract_id(self) -> str:
        return _contract_stable_digest("queue_ownership_contract", self.canonical())


class RuntimeContractViolation(RuntimeError):
    pass


class RuntimeContractRegistry:
    """Small deterministic registry for explicit queue ownership."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._contracts: dict[str, QueueOwnershipContract] = {}

    def register_queue(self, contract: QueueOwnershipContract | Mapping[str, object]) -> QueueOwnershipContract:
        if not isinstance(contract, QueueOwnershipContract):
            items = no_hook_mapping_items(contract)
            if items is None:
                exception_message = "queue ownership contract is not an owned mapping"
                raise RuntimeContractViolation(exception_message)
            payload = dict(items)
            contract = QueueOwnershipContract(**payload)
        canonical = contract.canonical()
        queue_id = canonical["queue_id"]
        with self._lock:
            existing = self._contracts.get(queue_id)
            if existing and existing.contract_id != contract.contract_id:
                exception_message = "queue ownership conflict"
                raise RuntimeContractViolation(exception_message)
            self._contracts[queue_id] = contract
        return contract

    def require_owner(self, queue_id: str, owner_domain: str) -> QueueOwnershipContract:
        queue_key = _contract_text(queue_id, "")
        requested_owner = _contract_text(owner_domain, "")
        with self._lock:
            contract = self._contracts.get(queue_key)
        if not contract:
            exception_message = "queue has no ownership contract"
            raise RuntimeContractViolation(exception_message)
        if contract.canonical()["owner_domain"] != requested_owner:
            exception_message = "queue owner mismatch"
            raise RuntimeContractViolation(exception_message)
        return contract

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            rows = []
            for qid, contract in dict.items(self._contracts):
                rows.append((qid, contract.canonical()))
            return dict(sorted(rows, key=lambda row: row[0]))


__all__ = ("QueueOwnershipContract", "RuntimeContractRegistry", "RuntimeContractViolation")
