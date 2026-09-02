"""Bounded typed operations for the queue identity index."""
from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_text
from Virus_Scan.scheduler.queue import identity_index_storage
from Virus_Scan.scheduler.queue.identity_index_contract import (
    IdentityIndexLookupOutcome,
    IdentityIndexMutationOutcome,
    identity_index_lookup_outcome,
    identity_index_mutation_outcome,
    identity_index_nonnegative_float,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    import os

ReportIssue = Callable[[object, BaseException | str], str]
StorageReport = Callable[[str, BaseException | str], None]


def _index_dir(
    queue_dir: os.PathLike[str] | str, *, failure_stage: str, report_issue: ReportIssue
) -> tuple[Path | None, str]:
    path = None
    reason = ""
    try:
        path = identity_index_storage.index_dir(queue_dir)
    except (OSError, TypeError, ValueError) as exc:
        report_issue(failure_stage, exc)
        reason = failure_stage
    return path, reason


def _index_items(
    path: Path, *, failure_stage: str, report_issue: ReportIssue
) -> tuple[tuple[Path, ...], str]:
    items: tuple[Path, ...] = ()
    reason = ""
    try:
        items = tuple(sorted(path.glob("*.json")))
    except OSError as exc:
        report_issue(failure_stage, exc)
        reason = failure_stage
    return items, reason


def _identity_text(identity: object, report_issue: ReportIssue) -> tuple[str, str]:
    text, reason = scheduler_text(
        identity,
        unsupported_reason="queue_identity_index_identity_rejected",
    )
    if reason or text == "":
        failure_reason = reason or "queue_identity_index_identity_missing"
        report_issue("identity_rejected", ValueError(failure_reason))
        return "", failure_reason
    return text, ""


def note_identity_for_queue_outcome(
    queue_dir: os.PathLike[str] | str,
    identity: object,
    *,
    report_issue: ReportIssue,
    storage_report: StorageReport,
) -> IdentityIndexMutationOutcome:
    identity_text, identity_reason = _identity_text(identity, report_issue)
    if identity_reason:
        return identity_index_mutation_outcome("rejected", identity_reason)
    path, path_reason = _index_dir(
        queue_dir, failure_stage="queue_dir_rejected", report_issue=report_issue
    )
    if path_reason or path is None:
        return identity_index_mutation_outcome("failed", path_reason or "queue_dir_rejected")
    if not path.exists():
        return identity_index_mutation_outcome("skipped", "identity_index_dir_missing")
    items, scan_reason = _index_items(
        path, failure_stage="identity_index_scan_failed", report_issue=report_issue
    )
    if scan_reason:
        return identity_index_mutation_outcome("failed", scan_reason)
    touched = 0
    write_failed = False
    for item in items:
        payload = identity_index_storage.read_index(item, storage_report)
        if payload is None:
            continue
        identities = identity_index_storage.identity_snapshot(dict.get(payload, "ids"), storage_report)
        if identities is None:
            continue
        updated = set(identities)
        updated.add(identity_text)
        if identity_index_storage.write_index(item, updated, storage_report):
            touched += 1
        else:
            write_failed = True
    if write_failed:
        return identity_index_mutation_outcome(
            "failed", "identity_index_write_failed", touched_entries=touched
        )
    return identity_index_mutation_outcome(
        "completed", "identity_index_updated", touched_entries=touched
    )


def get_index_entry_outcome(
    key: tuple[object, ...],
    ttl_sec: object,
    *,
    report_issue: ReportIssue,
    storage_report: StorageReport,
) -> IdentityIndexLookupOutcome:
    path = identity_index_storage.index_path_for_key(key, storage_report)
    if path is None:
        return identity_index_lookup_outcome("rejected", "identity_index_path_unavailable")
    payload = None
    read_failure_reason = ""
    try:
        payload = identity_index_storage.read_index(path, storage_report)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        report_issue("read_failed", exc)
        read_failure_reason = "read_failed"
    if read_failure_reason:
        return identity_index_lookup_outcome("failed", read_failure_reason)
    if payload is None:
        return identity_index_lookup_outcome("miss", "identity_index_payload_missing")
    timestamp = identity_index_nonnegative_float(
        dict.get(payload, "time"),
        reason="queue_identity_index_timestamp_rejected",
    )
    ttl = identity_index_nonnegative_float(ttl_sec, reason="queue_identity_index_ttl_rejected")
    if not timestamp.accepted or not ttl.accepted:
        failure_reason = timestamp.reason or ttl.reason
        report_issue("timestamp_failed", ValueError(failure_reason))
        return identity_index_lookup_outcome("rejected", failure_reason)
    if time.time() - timestamp.value > ttl.value:
        return identity_index_lookup_outcome("expired", "identity_index_entry_expired")
    identities = identity_index_storage.identity_snapshot(dict.get(payload, "ids"), storage_report)
    if identities is None:
        return identity_index_lookup_outcome("rejected", "identity_index_identities_rejected")
    return identity_index_lookup_outcome("hit", "identity_index_entry_found", identities)


def invalidate_queue_outcome(
    queue_dir: os.PathLike[str] | str | None,
    *,
    report_issue: ReportIssue,
) -> IdentityIndexMutationOutcome:
    if queue_dir is None:
        return identity_index_mutation_outcome("skipped", "queue_dir_not_supplied")
    path, path_reason = _index_dir(
        queue_dir, failure_stage="invalidate_queue_dir_rejected", report_issue=report_issue
    )
    if path_reason or path is None:
        return identity_index_mutation_outcome("failed", path_reason or "invalidate_queue_dir_rejected")
    if not path.exists():
        return identity_index_mutation_outcome("skipped", "identity_index_dir_missing")
    items, scan_reason = _index_items(
        path, failure_stage="invalidate_scan_failed", report_issue=report_issue
    )
    if scan_reason:
        return identity_index_mutation_outcome("failed", scan_reason)
    touched = 0
    for item in items:
        unlink_reason = ""
        try:
            item.unlink()
            touched += 1
        except OSError as exc:
            report_issue("invalidate_failed", exc)
            unlink_reason = "invalidate_failed"
        if unlink_reason:
            return identity_index_mutation_outcome("failed", unlink_reason, touched_entries=touched)
    return identity_index_mutation_outcome("completed", "identity_index_invalidated", touched_entries=touched)


def set_index_entry_outcome(
    key: tuple[object, ...],
    identities: Iterable[str],
    *,
    max_entries: int,
    storage_report: StorageReport,
) -> IdentityIndexMutationOutcome:
    path = identity_index_storage.index_path_for_key(key, storage_report)
    if path is None:
        return identity_index_mutation_outcome("rejected", "identity_index_path_unavailable")
    if not identity_index_storage.write_index(path, identities, storage_report):
        return identity_index_mutation_outcome("rejected", "identity_index_write_rejected")
    identity_index_storage.prune_index_dir(path.parent, max_entries=max_entries, report=storage_report)
    return identity_index_mutation_outcome("completed", "identity_index_written", touched_entries=1)
