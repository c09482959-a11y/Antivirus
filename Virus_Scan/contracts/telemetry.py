"""Neutral telemetry contracts for bootstrap-safe model/runtime error reporting.

This module is intentionally independent of runtime dependency-provider modules so
model code can report degraded/error conditions without importing scanner/runtime
callable registries.  It owns the small deterministic context materialization
contract used by lightweight error records.
"""
from __future__ import annotations

from typing import Mapping
import sys
import time

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_duplicate_key, no_hook_json_sort_key, no_hook_mapping_items, no_hook_materialize, no_hook_text


def _telemetry_text(value: object, *, replacement_text: str = "unknown") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_telemetry_text",
        unsupported_reason="unsafe_telemetry_text_value_rejected",
    )
    if reason or text == "":
        replacement, replacement_reason = no_hook_text(
            replacement_text,
            missing_reason="missing_telemetry_default",
            unsupported_reason="unsafe_telemetry_default_rejected",
        )
        return "" if replacement_reason else str.strip(replacement)
    return str.strip(text)


def _telemetry_json_key(index: int) -> str:
    return "telemetry_context_key_" + int.__str__(index)


def _telemetry_materialize(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        out: dict[str, object] = {}
        keyed = []
        for index, (key, item) in enumerate(items):
            key_text, key_reason = no_hook_text(
                key,
                missing_reason="missing_telemetry_context_key",
                unsupported_reason="invalid_telemetry_context_key",
            )
            if key_reason or key_text == "":
                key_text = _telemetry_json_key(index)
            keyed.append((key_text, index, item))
        for raw_key_text, index, item in sorted(keyed, key=lambda row: (row[0], row[1])):
            key_text = raw_key_text
            if key_text in out:
                key_text = no_hook_duplicate_key(key_text, index)
            out[key_text] = _telemetry_materialize(item)
        return out
    if type(value) is tuple:
        return tuple(_telemetry_materialize(item) for item in value)
    if type(value) is list:
        return [_telemetry_materialize(item) for item in value]
    if type(value) in (set, frozenset):
        return sorted((_telemetry_materialize(item) for item in value), key=no_hook_json_sort_key)
    return no_hook_materialize(value, reason_prefix="telemetry_context")


def materialize_telemetry_context(value: object) -> object:
    """Return a detached, deterministic, JSON-like telemetry value.

    Unknown caller-owned mappings/iterables/objects are rejected with explicit
    evidence by the canonical no-hook materializer instead of being traversed,
    stringified, or sorted through caller-owned hooks.
    """
    return _telemetry_materialize(value)


def log_error(msg: object) -> None:
    """Bootstrap-safe error logger used by model/runtime contracts."""
    try:
        sys.stderr.write("[ERROR] " + _telemetry_text(msg, replacement_text="telemetry_error_unavailable") + "\n")
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _ = exc


def record_detector_error(
    detector_name: str,
    exc: BaseException | str,
    context: Mapping[str, object] | None = None,
    **context_fields: object,
) -> dict[str, object]:
    """Return a structured detector error record without dependency registries."""
    ctx = materialize_telemetry_context(context if context is not None else {})
    if type(ctx) is not dict:
        ctx = {"context": ctx}
    if context_fields:
        extra_ctx = materialize_telemetry_context(context_fields)
        if type(extra_ctx) is dict:
            ctx.update(extra_ctx)
        else:
            ctx["context_fields"] = extra_ctx
    return {
        "detector": _telemetry_text(detector_name, replacement_text="unknown") or "unknown",
        "error": _telemetry_text(exc, replacement_text="detector_error_unavailable"),
        "context": materialize_telemetry_context(ctx),
        "time": time.time(),
    }


__all__ = (
    "log_error",
    "materialize_telemetry_context",
    "record_detector_error",
)
