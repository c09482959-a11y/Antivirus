"""Canonical scheduler-owned queue state JSON reads.

Batch 2 scheduler ownership: live queue state consumed by reconciliation and
quarantine must be read through one explicit scheduler owner.  This module is
intentionally narrow: it reads a queue JSON file, validates that the payload is
a JSON object suitable for queue state, and returns an immutable snapshot.
Read, decode, semantic, and shape failures are raised to callers so recovery
telemetry can report the real queue IO defect instead of continuing with a
hidden default payload.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_path
from Virus_Scan.scheduler.runtime.queue_json import validate_persistent_record_semantics

if TYPE_CHECKING:
    import os

QUEUE_STATE_READ_EXCEPTIONS = (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError)


def _freeze_queue_json_value(value: object) -> object:
    """Return an immutable JSON-safe snapshot for queue state values."""
    items = no_hook_mapping_items(value)
    if items is not None:
        frozen: dict[str, object] = {}
        for key, item in items:
            if type(key) is str:
                frozen[str.__str__(key)] = _freeze_queue_json_value(item)
        return MappingProxyType(frozen)
    if type(value) is list:
        return tuple(_freeze_queue_json_value(item) for item in value)
    if type(value) is tuple:
        return tuple(_freeze_queue_json_value(item) for item in value)
    return value


def read_queue_json_file(path: os.PathLike[str] | str) -> Mapping[str, object]:
    """Read one live queue JSON object as an immutable scheduler snapshot.

    Raises the underlying filesystem, decode, validation, or shape exception on
    failure.  Callers that quarantine/reconcile bad queue files must report that
    explicit failure rather than receiving an empty/default queue record.
    """
    queue_path = Path(path)
    with queue_path.open("r", encoding="utf-8", errors="strict") as handle:
        payload = json.load(handle)
    validate_persistent_record_semantics(payload, context="queue_state_read:" + str.__str__(queue_path.name))
    if no_hook_mapping_items(payload) is None:
        raise ValueError("queue JSON payload must be an object: " + scheduler_evidence_path(queue_path))
    return _freeze_queue_json_value(payload)


__all__ = ("QUEUE_STATE_READ_EXCEPTIONS", "read_queue_json_file")
