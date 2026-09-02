"""Schema normalization and semantic verification for scheduler queue JSON."""
from __future__ import annotations

import json

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.runtime.queue_json_schema_semantics import (
    has_queue_json_semantic_keys,
    queue_json_schema_context,
    validate_persistent_record_semantics_mapping,
)

QUEUE_JSON_SCHEMA_SEMANTIC_KEYS = frozenset(
    {
        "job_type",
        "failure_info",
        "queue_info",
        "queue_identity",
        "record_type",
        "result",
        "results",
        "file",
        "file_id",
        "quarantined",
        "error_info",
        "scan_result",
    }
)


def normalize_persistent_record_schema(value: object, *, default_schema_version: int = 1) -> object:
    """Add and normalize scheduler durable-record schema version metadata."""
    if type(value) is not dict:
        return value
    out = dict(value)
    default_version, _default_reason = scheduler_int(
        default_schema_version,
        default=1,
        minimum=1,
        reason="queue_json_schema_default_rejected",
    )
    if "schema_version" not in out and any(key in out for key in QUEUE_JSON_SCHEMA_SEMANTIC_KEYS):
        out["schema_version"] = default_version
    if "schema_version" in out:
        schema_version, _schema_reason = scheduler_int(
            dict.get(out, "schema_version"),
            default=default_version,
            minimum=1,
            reason="queue_json_schema_version_rejected",
        )
        out["schema_version"] = schema_version
    return out


def validate_persistent_record_semantics(value: object, *, context: str = "persistent_json") -> bool:
    """Validate durable scheduler queue/result/replay JSON semantics."""
    if type(value) is not dict:
        return True
    if not has_queue_json_semantic_keys(value):
        return True
    context_text = queue_json_schema_context(context)
    validate_persistent_record_semantics_mapping(value, context_text=context_text)
    return True


def verify_persistent_json_file(
    path: object,
    expected: object = None,
    *,
    context: str = "persistent_json",
    require_match: bool = False,
) -> object:
    """Read and validate a durable scheduler JSON file after publication."""
    with open(path, "r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    validate_persistent_record_semantics(loaded, context=context)
    if require_match and expected is not None and loaded != expected:
        raise ValueError(queue_json_schema_context(context) + ": readback mismatch after publication")
    return loaded


_queue_json_schema_context = queue_json_schema_context
_normalize_persistent_record_schema = normalize_persistent_record_schema
_validate_persistent_record_semantics = validate_persistent_record_semantics
_verify_persistent_json_file = verify_persistent_json_file
