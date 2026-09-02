"""Queue-local identity index for process/raw queue coordination."""
from __future__ import annotations


from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_text
from Virus_Scan.scheduler.queue import identity_index_operations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from Virus_Scan.scheduler.queue.identity_index_contract import (
        IdentityIndexLookupOutcome,
        IdentityIndexMutationOutcome,
    )
    from collections.abc import Iterable
    import os

QUEUE_IDENTITY_INDEX_MAX_ENTRIES = 64


def _record_identity_index_issue(
    where: object,
    exc: BaseException | str,
) -> str:
    stage, reason = scheduler_text(
        where,
        replacement_text="",
        unsupported_reason="queue_identity_index_stage_rejected",
    )
    if reason or stage == "":
        stage = "issue"
    return record_scheduler_suppressed("queue_identity_index_" + stage, exc)


def _report_identity_index_issue(where: str, exc: BaseException | str) -> None:
    _record_identity_index_issue(where, exc)


def note_identity_for_queue_outcome(
    queue_dir: os.PathLike[str] | str,
    identity: object,
) -> IdentityIndexMutationOutcome:
    return identity_index_operations.note_identity_for_queue_outcome(
        queue_dir,
        identity,
        report_issue=_record_identity_index_issue,
        storage_report=_report_identity_index_issue,
    )


def note_identity_for_queue(
    queue_dir: os.PathLike[str] | str,
    identity: str,
) -> None:
    note_identity_for_queue_outcome(queue_dir, identity)


def get_index_entry_outcome(
    key: tuple[object, ...],
    ttl_sec: object,
) -> IdentityIndexLookupOutcome:
    return identity_index_operations.get_index_entry_outcome(
        key,
        ttl_sec,
        report_issue=_record_identity_index_issue,
        storage_report=_report_identity_index_issue,
    )


def get_index_entry(
    key: tuple[object, ...],
    ttl_sec: float,
) -> set[str] | None:
    outcome = get_index_entry_outcome(key, ttl_sec)
    return set(outcome.identities) if outcome.status == "hit" else None


def invalidate_queue_outcome(
    queue_dir: os.PathLike[str] | str | None = None,
) -> IdentityIndexMutationOutcome:
    return identity_index_operations.invalidate_queue_outcome(
        queue_dir,
        report_issue=_record_identity_index_issue,
    )


def invalidate_queue(
    queue_dir: os.PathLike[str] | str | None = None,
) -> None:
    invalidate_queue_outcome(queue_dir)


def set_index_entry_outcome(
    key: tuple[object, ...],
    identities: Iterable[str],
) -> IdentityIndexMutationOutcome:
    return identity_index_operations.set_index_entry_outcome(
        key,
        identities,
        max_entries=QUEUE_IDENTITY_INDEX_MAX_ENTRIES,
        storage_report=_report_identity_index_issue,
    )


def set_index_entry(
    key: tuple[object, ...],
    identities: Iterable[str],
) -> None:
    set_index_entry_outcome(key, identities)


__all__ = (
    "QUEUE_IDENTITY_INDEX_MAX_ENTRIES",
    "get_index_entry",
    "get_index_entry_outcome",
    "invalidate_queue",
    "invalidate_queue_outcome",
    "note_identity_for_queue",
    "note_identity_for_queue_outcome",
    "set_index_entry",
    "set_index_entry_outcome",
)
