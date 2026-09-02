"""Queue-owned retry integrity read/schema helpers."""
from __future__ import annotations

from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.queue.retry_integrity_decisions import (
    retry_integrity_mapping_decision,
    retry_integrity_missing_decision,
)
from Virus_Scan.scheduler.queue.retry_policy_callback_safety import (
    RETRY_POLICY_EXCEPTIONS,
    record_retry_policy_callback_failure,
    retry_policy_callback_error,
    retry_policy_callback_supported,
)


def safe_get_integrity(
    *,
    get_integrity: Callable[[object], Mapping[str, object]],
    path: object,
    attempt: int,
    retry_failures: list[dict[str, object]],
) -> Mapping[str, object]:
    if not retry_policy_callback_supported(get_integrity):
        evidence = record_retry_policy_callback_failure(
            retry_failures=retry_failures,
            path=path,
            attempt=attempt,
            callback_name="get_integrity",
            error=retry_policy_callback_error(get_integrity, "get_integrity"),
        )
        return evidence.as_scan_integrity()
    try:
        integrity = get_integrity(path)
    except RETRY_POLICY_EXCEPTIONS as exc:
        evidence = record_retry_policy_callback_failure(
            retry_failures=retry_failures,
            path=path,
            attempt=attempt,
            callback_name="get_integrity",
            error=exc,
        )
        return evidence.as_scan_integrity()
    if integrity is None or (type(integrity) is str and str.__str__(integrity) == ""):
        return retry_integrity_missing_decision(integrity).as_integrity()
    owned = retry_integrity_mapping_decision(integrity).as_optional_mapping()
    if owned is not None:
        return owned
    evidence = record_retry_policy_callback_failure(
        retry_failures=retry_failures,
        path=path,
        attempt=attempt,
        callback_name="get_integrity_schema",
        error=TypeError("get_integrity must return a mapping, got " + no_hook_type_name(integrity)),
    )
    return evidence.as_scan_integrity()


def safe_result_scan_integrity(
    *,
    result: Mapping[str, object],
    path: object,
    attempt: int,
    get_integrity: Callable[[object], Mapping[str, object]],
    retry_failures: list[dict[str, object]],
) -> Mapping[str, object]:
    result_items = no_hook_mapping_items(result)
    result_record = dict(result_items) if result_items is not None else {}
    raw_integrity = dict.get(result_record, "scan_integrity")
    if raw_integrity is None or (type(raw_integrity) is str and str.__str__(raw_integrity) == ""):
        return safe_get_integrity(
            get_integrity=get_integrity,
            path=path,
            attempt=attempt,
            retry_failures=retry_failures,
        )
    owned = retry_integrity_mapping_decision(raw_integrity).as_optional_mapping()
    if owned is not None:
        return owned
    evidence = record_retry_policy_callback_failure(
        retry_failures=retry_failures,
        path=path,
        attempt=attempt,
        callback_name="result_scan_integrity_schema",
        error=TypeError("result scan_integrity must be a mapping, got " + no_hook_type_name(raw_integrity)),
    )
    return evidence.as_scan_integrity()


__all__ = ("safe_get_integrity", "safe_result_scan_integrity")
