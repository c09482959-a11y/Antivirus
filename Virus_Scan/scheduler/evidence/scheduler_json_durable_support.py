"""No-hook support for durable scheduler JSON publication."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scheduler.internal.path_text import scheduler_posix_path_text as durable_path_text

RAW_JSON_CLEANUP_CONTEXT = "raw_json_cleanup"
RAW_JSON_PUBLISH_CONTEXT = "raw_json_publish"
PROCESS_QUEUE_JSON_CONTEXT = "process_queue_json"
RAW_JSON_OPERATION_FAILED = False
RAW_JSON_OPERATION_SUCCEEDED = True

_BAD_FINAL_CLEANUP_SUFFIX = "_bad_final_cleanup"
_DURABILITY_CLEANUP_SUFFIX = "_durability_cleanup"
_DURABILITY_TMP_CLEANUP_SUFFIX = "_durability_tmp_cleanup"
_DURABLE_WRITE_FAILED_SUFFIX = "_durable_write_failed"
_FAILED_SUFFIX = "_failed"
_FAILED_FINAL_CLEANUP_SUFFIX = "_failed_final_cleanup"
_FAILED_FINAL_PROBE_SUFFIX = "_failed_final_probe"
_FINAL_SUFFIX = "_final"
_TMP_CLEANUP_SUFFIX = "_tmp_cleanup"
_TMP_SUFFIX = "_tmp"


def durable_context_text(value: object, *, default_text: str, unsupported_reason: str) -> tuple[str, str]:
    text, reason = no_hook_text(
        value,
        missing_reason="durable_json_context_missing",
        unsupported_reason=unsupported_reason,
    )
    if reason == "" and text:
        return text, ""
    return default_text, reason


def context_failed(base: str) -> str:
    return str.__add__(base, _FAILED_SUFFIX)


def context_tmp(base: str) -> str:
    return str.__add__(base, _TMP_SUFFIX)


def context_final(base: str) -> str:
    return str.__add__(base, _FINAL_SUFFIX)


def context_tmp_cleanup(base: str) -> str:
    return str.__add__(base, _TMP_CLEANUP_SUFFIX)


def context_bad_final_cleanup(base: str) -> str:
    return str.__add__(base, _BAD_FINAL_CLEANUP_SUFFIX)


def context_durability_cleanup(base: str) -> str:
    return str.__add__(base, _DURABILITY_CLEANUP_SUFFIX)


def context_durability_tmp_cleanup(base: str) -> str:
    return str.__add__(base, _DURABILITY_TMP_CLEANUP_SUFFIX)


def context_failed_final_probe(base: str) -> str:
    return str.__add__(base, _FAILED_FINAL_PROBE_SUFFIX)


def context_failed_final_cleanup(base: str) -> str:
    return str.__add__(base, _FAILED_FINAL_CLEANUP_SUFFIX)


def context_durable_write_failed(base: str) -> str:
    return str.__add__(base, _DURABLE_WRITE_FAILED_SUFFIX)


__all__ = (
    "PROCESS_QUEUE_JSON_CONTEXT",
    "RAW_JSON_CLEANUP_CONTEXT",
    "RAW_JSON_OPERATION_FAILED",
    "RAW_JSON_OPERATION_SUCCEEDED",
    "RAW_JSON_PUBLISH_CONTEXT",
    "context_bad_final_cleanup",
    "context_durability_cleanup",
    "context_durability_tmp_cleanup",
    "context_durable_write_failed",
    "context_failed",
    "context_failed_final_cleanup",
    "context_failed_final_probe",
    "context_final",
    "context_tmp",
    "context_tmp_cleanup",
    "durable_context_text",
    "durable_path_text",
)
