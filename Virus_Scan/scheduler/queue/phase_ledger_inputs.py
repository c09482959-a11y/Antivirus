"""No-hook input materializers for queue phase ledger boundaries."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
)
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from Virus_Scan.scheduler.queue.recovery_contracts import QueueWorkerFailureAccounting
from Virus_Scan.scheduler.queue.snapshots import QueueBehaviorSnapshot

_SEQ_TYPES = (list, tuple, set, frozenset)
_WORKER_FAILURE_ACCOUNTING_INPUT_REJECTED = "scheduler worker failure accounting input rejected"
_WORKER_FAILURE_ACCOUNTING_NOT_CANONICAL = "scheduler worker failure accounting is not immutable/canonical"


def owned_string_mapping(value: object, error_text: str) -> dict[str, object]:
    items = no_hook_mapping_items(value)
    if items is None:
        raise RuntimeError(error_text)
    return scheduler_str_key_mapping_from_items(items)


def owned_phase_snapshots(value: object) -> tuple[QueueBehaviorSnapshot, ...]:
    return tuple(
        item
        for item in no_hook_sequence_items(value)
        if isinstance(item, QueueBehaviorSnapshot)
    )


def owned_worker_failures(value: object) -> tuple[QueueWorkerFailureAccounting, ...]:
    records = no_hook_sequence_items(value)
    if not records and value is not None and type(value) not in _SEQ_TYPES:
        raise RuntimeError(_WORKER_FAILURE_ACCOUNTING_INPUT_REJECTED)
    out: list[QueueWorkerFailureAccounting] = []
    for record in records:
        if not isinstance(record, QueueWorkerFailureAccounting):
            raise TypeError(_WORKER_FAILURE_ACCOUNTING_NOT_CANONICAL)
        out.append(record)
    return tuple(out)
