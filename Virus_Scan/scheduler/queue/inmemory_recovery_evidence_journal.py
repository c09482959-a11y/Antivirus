"""Append-efficient recovery evidence ownership for the in-memory scheduler."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_items
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.queue.inmemory_cancel_evidence import cancel_evidence_identity


def _journal_projection_failure(
    value: object, *, channel: str, index: int | None, reason: str
) -> Mapping[str, object]:
    field_name = channel if index is None else channel + "[" + int.__str__(index) + "]"
    record = unsupported_scheduler_value_evidence(value, field_name=field_name)
    record["stage"] = "inmemory_recovery_evidence_journal"
    record["reason"] = reason
    record["error_source"] = "scheduler.queue.inmemory_recovery_evidence_journal"
    return immutable_mapping(record)


def _validated_records(
    records: object, *, channel: str
) -> tuple[Mapping[str, object], ...]:
    if type(records) not in (tuple, list):
        return (
            _journal_projection_failure(
                records,
                channel=channel,
                index=None,
                reason="recovery_evidence_sequence_rejected",
            ),
        )
    projected: list[Mapping[str, object]] = []
    for index, record in enumerate(no_hook_sequence_items(records)):
        if scheduler_mapping_items(record) is None:
            projected.append(
                _journal_projection_failure(
                    record,
                    channel=channel,
                    index=index,
                    reason="recovery_evidence_record_rejected",
                )
            )
            continue
        projected.append(immutable_mapping(record))
    return tuple(projected)


def _validated_cursor(cursor: object, *, count: int, channel: str) -> int:
    if type(cursor) is not int:
        raise TypeError(channel + "_cursor_must_be_int")
    if cursor < 0:
        raise ValueError(channel + "_cursor_negative")
    if cursor > count:
        raise ValueError(channel + "_cursor_ahead_of_journal")
    return cursor


class InMemoryRecoveryEvidenceJournal:
    """One append-efficient owner for retry, cancel, and empty-drain evidence.

    Counts are O(1), appends are amortized O(1) per record, and cursor reads are
    O(delta). Full immutable snapshots are explicit O(N) operations.
    """

    __slots__ = (
        "_retry_records",
        "_cancel_records",
        "_empty_drain_records",
        "_cancel_identities",
    )

    def __init__(self) -> None:
        self._retry_records: list[Mapping[str, object]] = []
        self._cancel_records: list[Mapping[str, object]] = []
        self._empty_drain_records: list[Mapping[str, object]] = []
        self._cancel_identities: set[tuple[object, ...]] = set()

    def retry_count(self) -> int:
        return len(self._retry_records)

    def retry_since(self, cursor: object) -> tuple[Mapping[str, object], ...]:
        start = _validated_cursor(cursor, count=len(self._retry_records), channel="retry_evidence")
        return tuple(self._retry_records[start:])

    def retry_snapshot(self) -> tuple[Mapping[str, object], ...]:
        return tuple(self._retry_records)

    def append_retry(self, records: object) -> int:
        projected = _validated_records(records, channel="retry_recovery_evidence")
        self._retry_records.extend(projected)
        return len(projected)

    def cancel_count(self) -> int:
        return len(self._cancel_records)

    def cancel_since(self, cursor: object) -> tuple[Mapping[str, object], ...]:
        start = _validated_cursor(cursor, count=len(self._cancel_records), channel="cancel_evidence")
        return tuple(self._cancel_records[start:])

    def cancel_snapshot(self) -> tuple[Mapping[str, object], ...]:
        return tuple(self._cancel_records)

    def append_cancel(self, records: object) -> int:
        projected = _validated_records(records, channel="cancel_only_evidence")
        appended = 0
        for record in projected:
            identity = cancel_evidence_identity(record)
            if identity in self._cancel_identities:
                continue
            self._cancel_identities.add(identity)
            self._cancel_records.append(record)
            appended += 1
        return appended

    def empty_drain_snapshot(self) -> tuple[Mapping[str, object], ...]:
        return tuple(self._empty_drain_records)

    def replace_empty_drain(self, records: object, *, mirror_retry: bool = True) -> int:
        projected = _validated_records(records, channel="empty_drain_recovery_evidence")
        self._empty_drain_records[:] = projected
        if mirror_retry and projected:
            self._retry_records.extend(projected)
        return len(projected)

    def append_empty_drain(self, records: object, *, mirror_retry: bool = True) -> int:
        projected = _validated_records(records, channel="empty_drain_recovery_evidence")
        self._empty_drain_records.extend(projected)
        if mirror_retry and projected:
            self._retry_records.extend(projected)
        return len(projected)


__all__ = ("InMemoryRecoveryEvidenceJournal",)
