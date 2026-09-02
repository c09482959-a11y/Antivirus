"""Durable scheduler JSON filesystem publication."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.evidence.process_queue_errors import record_scheduler_suppressed
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace, queue_safe_unlink
from Virus_Scan.scheduler.runtime.queue_json import (
    make_json_safe,
    validate_persistent_record_semantics,
    verify_persistent_json_file,
)
from Virus_Scan.runtime.api import flush_open_writable_file
from Virus_Scan.scheduler.evidence.scheduler_json_durable_support import (
    PROCESS_QUEUE_JSON_CONTEXT, RAW_JSON_CLEANUP_CONTEXT, RAW_JSON_OPERATION_FAILED, RAW_JSON_OPERATION_SUCCEEDED, RAW_JSON_PUBLISH_CONTEXT,
    context_bad_final_cleanup, context_durability_cleanup, context_durability_tmp_cleanup, context_durable_write_failed, context_failed,
    context_failed_final_cleanup, context_failed_final_probe, context_final, context_tmp, context_tmp_cleanup, durable_context_text, durable_path_text,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True)
class RawQueueJsonDependencies:
    make_json_safe: Callable[[object], object]
    validate_persistent_record_semantics: Callable[..., object]
    verify_persistent_json_file: Callable[..., object]
    runtime_value: Callable[..., object]
    record_suppressed: Callable[[str, BaseException], object]
    recoverable_exceptions: tuple[type[BaseException], ...] = RAW_QUEUE_RECOVERABLE_EXCEPTIONS


def raw_unlink_quiet(path: object, *, log_context: str, deps: RawQueueJsonDependencies) -> bool:
    safe_path, path_reason = scheduler_filesystem_path(path)
    safe_context, context_reason = durable_context_text(
        log_context,
        default_text=RAW_JSON_CLEANUP_CONTEXT,
        unsupported_reason="raw_json_cleanup_context_rejected",
    )
    if path_reason:
        try:
            deps.record_suppressed("raw_json_cleanup_path_rejected", ValueError(path_reason))
        except deps.recoverable_exceptions as suppressed_exc:
            _ = suppressed_exc
        return RAW_JSON_OPERATION_FAILED
    if context_reason:
        try:
            deps.record_suppressed("raw_json_cleanup_context_rejected", ValueError(context_reason))
        except deps.recoverable_exceptions as suppressed_exc:
            _ = suppressed_exc
    try:
        removed = queue_safe_unlink(safe_path, log_context=safe_context)
    except deps.recoverable_exceptions as cleanup_exc:
        deps.record_suppressed(context_failed(safe_context), cleanup_exc)
        return RAW_JSON_OPERATION_FAILED
    if removed is not True:
        deps.record_suppressed(
            context_failed(safe_context),
            RuntimeError("raw queue cleanup owner returned failure"),
        )
        return RAW_JSON_OPERATION_FAILED
    return RAW_JSON_OPERATION_SUCCEEDED


def write_json_durable(tmp: object, final: object, payload: object, *, log_context: str = "raw_json_publish", deps: RawQueueJsonDependencies) -> bool:
    safe_tmp, tmp_reason = scheduler_filesystem_path(tmp)
    safe_final, final_reason = scheduler_filesystem_path(final)
    safe_context, context_reason = durable_context_text(
        log_context,
        default_text=RAW_JSON_PUBLISH_CONTEXT,
        unsupported_reason="raw_json_context_rejected",
    )
    if tmp_reason or final_reason or context_reason:
        try:
            deps.record_suppressed(
                "raw_json_durable_boundary_rejected",
                ValueError(tmp_reason or final_reason or context_reason),
            )
        except deps.recoverable_exceptions as suppressed_exc:
            _ = suppressed_exc
        return RAW_JSON_OPERATION_FAILED
    tmp_path, final_path = Path(safe_tmp), Path(safe_final)
    expected = None
    try:
        expected = deps.make_json_safe(payload)
        deps.validate_persistent_record_semantics(expected, context=safe_context)
        tmp_path.parent.mkdir(parents=True, exist_ok=True)
        final_path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(expected, fh, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            fh.flush()
            flush_open_writable_file(fh.fileno())
        deps.verify_persistent_json_file(tmp_path, expected=expected, context=context_tmp(safe_context), require_match=True)
        if queue_atomic_replace(tmp_path, final_path, log_context=safe_context) is not True:
            raw_unlink_quiet(tmp_path, log_context=context_tmp_cleanup(safe_context), deps=deps)
            return RAW_JSON_OPERATION_FAILED
        try:
            deps.verify_persistent_json_file(final_path, expected=expected, context=context_final(safe_context), require_match=True)
        except deps.recoverable_exceptions + (AssertionError,) as verify_exc:
            raw_unlink_quiet(final_path, log_context=context_bad_final_cleanup(safe_context), deps=deps)
            deps.record_suppressed("raw_json_final_verify_failed", verify_exc)
            return RAW_JSON_OPERATION_FAILED
        return RAW_JSON_OPERATION_SUCCEEDED
    except deps.recoverable_exceptions as exc:
        raw_unlink_quiet(tmp_path, log_context=context_durability_tmp_cleanup(safe_context), deps=deps)
        if expected is not None and final_path.exists():
            try:
                deps.verify_persistent_json_file(
                    final_path,
                    expected=expected,
                    context=context_failed_final_probe(safe_context),
                    require_match=True,
                )
            except deps.recoverable_exceptions + (AssertionError,):
                raw_unlink_quiet(final_path, log_context=context_failed_final_cleanup(safe_context), deps=deps)
        deps.record_suppressed("raw_json_durable_write_failed", exc)
        return RAW_JSON_OPERATION_FAILED


def write_process_queue_json_durable(tmp: object, final: object, payload: object, *, log_context: str = "process_queue_json") -> bool:
    safe_tmp, tmp_reason = scheduler_filesystem_path(tmp)
    safe_final, final_reason = scheduler_filesystem_path(final)
    safe_context, context_reason = durable_context_text(
        log_context,
        default_text=PROCESS_QUEUE_JSON_CONTEXT,
        unsupported_reason="process_queue_json_context_rejected",
    )
    if tmp_reason or final_reason or context_reason:
        record_scheduler_suppressed(
            "process_queue_json_boundary_rejected",
            ValueError(tmp_reason or final_reason or context_reason),
            extra={
                "tmp_type": no_hook_type_name(tmp),
                "final_type": no_hook_type_name(final),
                "context_type": no_hook_type_name(log_context),
            },
            fatal=True,
        )
        return RAW_JSON_OPERATION_FAILED
    tmp_path, final_path = Path(safe_tmp), Path(safe_final)
    try:
        expected = make_json_safe(payload)
        validate_persistent_record_semantics(expected, context=safe_context)
        final_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(expected, fh, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            fh.flush()
            flush_open_writable_file(fh.fileno())
        verify_persistent_json_file(tmp_path, expected=expected, context=context_tmp(safe_context), require_match=True)
        if queue_atomic_replace(tmp_path, final_path, log_context=safe_context) is not True:
            queue_safe_unlink(tmp_path, log_context=context_tmp_cleanup(safe_context))
            return RAW_JSON_OPERATION_FAILED
        verify_persistent_json_file(final_path, expected=expected, context=context_final(safe_context), require_match=True)
        return RAW_JSON_OPERATION_SUCCEEDED
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        try:
            queue_safe_unlink(tmp_path, log_context=context_durability_cleanup(safe_context))
        except (OSError, RuntimeError, TypeError, ValueError) as cleanup_exc:
            record_scheduler_suppressed(
                "process_queue_durable_cleanup_failed",
                cleanup_exc,
                extra={"log_context": safe_context, "tmp": durable_path_text(tmp_path)},
                fatal=False,
            )
        record_scheduler_suppressed(
            context_durable_write_failed(safe_context),
            exc,
            extra={"tmp": durable_path_text(tmp_path), "final": durable_path_text(final_path)},
            fatal=True,
        )
        return RAW_JSON_OPERATION_FAILED


__all__ = (
    "RawQueueJsonDependencies",
    "raw_unlink_quiet",
    "write_json_durable",
    "write_process_queue_json_durable",
)
