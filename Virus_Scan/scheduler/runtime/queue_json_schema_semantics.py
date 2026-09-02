"""Bounded semantic validators for scheduler queue JSON records."""
from __future__ import annotations

from Virus_Scan.contracts.result_record import (
    validate_result_collection_invariants as _contract_validate_result_collection_invariants,
    validate_result_record_invariants as _contract_validate_result_record_invariants,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_text

QUEUE_JSON_SEMANTIC_KEYS = frozenset(
    {
        "queue_failure",
        "failure_info",
        "queue_info",
        "queue_identity",
        "job_type",
        "record_type",
        "result",
        "results",
        "scan_result",
        "file",
        "file_path",
        "path",
        "file_id",
        "schema_version",
        "entries",
        "fast_entries",
        "replay",
        "replay_events",
    }
)
RESULT_CONTRACT_KEYS = frozenset(
    {
        "classification",
        "class",
        "verdict",
        "score",
        "error",
        "timed_out",
        "queue_failure",
    }
)
RESULT_IDENTITY_KEYS = frozenset({"file", "path", "node"})
FAILURE_CAUSAL_KEYS = ("error", "exception_type", "stage", "message")


def queue_json_schema_context(context: object) -> str:
    """Materialize a no-hook textual context for schema error reporting."""
    text, reason = scheduler_text(
        context,
        replacement_text="persistent_json",
        unsupported_reason="queue_json_schema_context_rejected",
    )
    return text if reason == "" and text else "persistent_json"


def has_queue_json_semantic_keys(value: dict[object, object]) -> bool:
    """Return whether an exact-dict queue record carries semantic contract fields."""
    return any(key in value for key in QUEUE_JSON_SEMANTIC_KEYS)


def validate_queue_failure_record(value: dict[object, object], *, context_text: str) -> None:
    """Validate explicit queue-failure records expose causal failure metadata."""
    if value.get("queue_failure") is not True:
        return
    failure_info = value.get("failure_info")
    if type(failure_info) is not dict or not failure_info:
        raise ValueError(context_text + ": queue_failure record missing non-empty failure_info")
    if not any(failure_info.get(key) for key in FAILURE_CAUSAL_KEYS):
        raise ValueError(context_text + ": failure_info lacks causal error metadata")


def validate_failure_info_object(value: dict[object, object], *, context_text: str) -> None:
    """Validate optional failure_info retains an object boundary when present."""
    failure_info = value.get("failure_info")
    if "failure_info" in value and failure_info is not None and type(failure_info) is not dict:
        raise ValueError(context_text + ": failure_info must be an object")


def reject_invalid_nested_result_boundary(
    value: dict[object, object],
    *,
    key: str,
    raw_nested: object,
    context_text: str,
) -> None:
    """Reject a present nested result value that is not an exact object."""
    if key in value and raw_nested is not None and type(raw_nested) is not dict:
        raise ValueError(context_text + ": " + key + " must be an object")


def copy_result_identity_if_missing(
    nested: dict[object, object],
    value: dict[object, object],
) -> None:
    """Copy the parent result identity into a nested result when needed."""
    if any(nested.get(identity_key) for identity_key in RESULT_IDENTITY_KEYS):
        return
    identity = value.get("file") or value.get("path") or value.get("node")
    if identity:
        nested["file"] = identity


def validate_nested_result_contract(
    nested: dict[object, object],
    *,
    context_text: str,
    key: str,
) -> None:
    """Validate nested result invariants only when contract fields exist."""
    if any(contract_key in nested for contract_key in RESULT_CONTRACT_KEYS):
        _contract_validate_result_record_invariants(nested, context=context_text + ":" + key)


def validate_nested_result_object(
    value: dict[object, object],
    *,
    key: str,
    context_text: str,
) -> None:
    """Validate one nested result object without collapsing missing identities."""
    raw_nested = value.get(key)
    reject_invalid_nested_result_boundary(
        value,
        key=key,
        raw_nested=raw_nested,
        context_text=context_text,
    )
    if type(raw_nested) is not dict:
        return
    nested = dict(raw_nested)
    copy_result_identity_if_missing(nested, value)
    validate_nested_result_contract(nested, context_text=context_text, key=key)


def validate_embedded_result_objects(value: dict[object, object], *, context_text: str) -> None:
    """Validate nested and top-level scheduler result record contracts."""
    for key in ("result", "scan_result"):
        validate_nested_result_object(value, key=key, context_text=context_text)
    has_verdict = any(key in value for key in ("classification", "class", "verdict", "score"))
    has_identity = any(key in value for key in RESULT_IDENTITY_KEYS)
    if has_verdict and has_identity:
        _contract_validate_result_record_invariants(value, context=context_text + ":result")


def validate_result_collection(value: dict[object, object], *, context_text: str) -> None:
    """Validate result collections when a durable record publishes them."""
    if "results" in value and value.get("results") is not None:
        _contract_validate_result_collection_invariants(value, context=context_text + ":results")


def validate_entry_maps(value: dict[object, object], *, context_text: str) -> None:
    """Validate replay and fast-entry containers retain object boundaries."""
    if "entries" in value and type(value.get("entries", {})) is not dict:
        raise ValueError(context_text + ": entries must be an object")
    if "fast_entries" in value and type(value.get("fast_entries", {})) is not dict:
        raise ValueError(context_text + ": fast_entries must be an object")


def validate_queue_identity(value: dict[object, object], *, context_text: str) -> None:
    """Validate queue job records expose a replayable file identity."""
    if not any(key in value for key in ("queue_info", "queue_identity")):
        return
    if not any(value.get(key) for key in ("file", "file_path", "path", "file_id", "queue_identity")):
        raise ValueError(context_text + ": queue job record lacks file identity")


def validate_persistent_record_semantics_mapping(
    value: dict[object, object],
    *,
    context_text: str,
) -> None:
    """Validate semantic queue JSON contracts for an exact-dict durable record."""
    validate_queue_failure_record(value, context_text=context_text)
    validate_failure_info_object(value, context_text=context_text)
    validate_embedded_result_objects(value, context_text=context_text)
    validate_result_collection(value, context_text=context_text)
    validate_entry_maps(value, context_text=context_text)
    validate_queue_identity(value, context_text=context_text)
