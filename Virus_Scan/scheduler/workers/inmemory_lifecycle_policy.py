"""Worker-owned in-memory lifecycle policy.

This module owns replay-stable lifecycle identifiers and parent watchdog
start-ownership classification for the in-memory scheduler.  It is intentionally
pure: callers pass the record/default values they already own and receive an
immutable scalar decision back.
"""

from __future__ import annotations

import hashlib
import json
from typing import Iterable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_float,
    scheduler_int,
    scheduler_path_text,
    scheduler_text,
)
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_decisions import worker_pre_execution_stage_decision

_INMEMORY_POLICY_EXCEPTIONS = (OSError, ValueError, TypeError, RuntimeError, KeyError, AttributeError)


def _lifecycle_path_text(value: object) -> str:
    text, reason = scheduler_path_text(value)
    if reason == "":
        return str.__str__(text).replace("\\", "/").casefold()
    return "<scheduler_path_rejected>"


def deterministic_lifecycle_epoch(root: object, all_files: Iterable[object] | None) -> int:
    """Return a stable scheduler lifecycle epoch for replay comparison."""
    files = tuple(
        sorted(
            (_lifecycle_path_text(item) for item in no_hook_sequence_items(all_files)),
            key=str.__str__,
        )
    )
    payload = {
        "root": _lifecycle_path_text(root),
        "files": files,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return int(digest[:8], 16) & 2147483647


def deterministic_worker_process_name(*, prefix: object, epoch: int, sequence: int) -> str:
    """Return a replay-stable worker process name without wall-clock entropy."""
    prefix_text, prefix_reason = scheduler_text(prefix, replacement_text="umige-inmem-r")
    if prefix_reason != "" or prefix_text == "":
        prefix_text = "umige-inmem-r"
    epoch_value, _epoch_reason = scheduler_int(epoch, default=0, minimum=0, reason="worker_lifecycle_epoch_rejected")
    sequence_value, _sequence_reason = scheduler_int(sequence, default=0, minimum=0, reason="worker_lifecycle_sequence_rejected")
    return str.__add__(
        str.__add__(prefix_text, int.__format__(epoch_value & 0x7FFFFFFF, "08x")),
        str.__add__("-", int.__format__(sequence_value, "05d")),
    )


def inmemory_stage_is_pre_execution(stage: object) -> bool:
    """Return True only for scheduler/setup stages that may wait briefly."""
    return worker_pre_execution_stage_decision(stage).value


def inmemory_start_wait_budget(record: Mapping[str, object] | None, default_seconds: float) -> float:
    """Bound queued/assigned wait before a worker proves execution."""
    record_items = no_hook_mapping_items(record)
    evidence = scheduler_mapping_item_value(record_items, "timeout_budget")
    evidence_items = no_hook_mapping_items(evidence)
    hard_source = scheduler_mapping_item_value(evidence_items, "timeout_budget")
    hard, _hard_reason = scheduler_float(
        hard_source,
        default=0.0,
        minimum=0.0,
        reason="worker_start_timeout_budget_rejected",
    )
    default_v, _default_reason = scheduler_float(
        default_seconds,
        default=0.0,
        minimum=0.0,
        reason="worker_start_default_budget_rejected",
    )
    bounded_default = default_v if default_v > 0.0 else 300.0
    if hard <= 0.0:
        return max(30.0, min(300.0, bounded_default))
    return max(30.0, min(bounded_default, 120.0, hard * 0.5))


__all__ = (
    "deterministic_lifecycle_epoch",
    "deterministic_worker_process_name",
    "inmemory_stage_is_pre_execution",
    "inmemory_start_wait_budget",
)
