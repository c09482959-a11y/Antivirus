"""Replayable typed decisions for raw queue integrity boundaries."""
from __future__ import annotations

from dataclasses import dataclass
from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_type_name
from Virus_Scan.scheduler.evidence_pairs import JsonEvidencePairs, scheduler_evidence_pairs

QueueIdentityFailureRecord = dict[str, object]


@dataclass(frozen=True)
class QueueIdentityFailureRecordsDecision:
    """Replayable decision for identity-collection failure records."""

    records: tuple[QueueIdentityFailureRecord, ...]
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


@dataclass(frozen=True)
class QueueExpectedFileCountDecision:
    """Replayable decision for expected raw-queue file counts."""

    count: int | None
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


def queue_identity_failure_records_decision(
    groups: object,
    *,
    failure_key: str,
) -> QueueIdentityFailureRecordsDecision:
    if type(groups) is not dict:
        reason = "queue_identity_groups_rejected"
        return QueueIdentityFailureRecordsDecision(
            records=(),
            accepted=False,
            reason=reason,
            evidence=scheduler_evidence_pairs(
                ("decision", "queue_identity_failure_records"),
                ("accepted", False),
                ("reason", reason),
                ("groups_type", no_hook_type_name(groups)),
            ),
        )
    records = dict.__getitem__(groups, failure_key) if failure_key in groups else None
    if records is None:
        reason = "queue_identity_failure_records_absent"
        return QueueIdentityFailureRecordsDecision(
            records=(),
            accepted=True,
            reason=reason,
            evidence=scheduler_evidence_pairs(
                ("decision", "queue_identity_failure_records"),
                ("accepted", True),
                ("reason", reason),
                ("record_count", 0),
            ),
        )
    if type(records) is list:
        record_tuple = tuple(records)
        return QueueIdentityFailureRecordsDecision(
            records=record_tuple,
            accepted=True,
            reason="queue_identity_failure_records_materialized",
            evidence=scheduler_evidence_pairs(
                ("decision", "queue_identity_failure_records"),
                ("accepted", True),
                ("reason", "queue_identity_failure_records_materialized"),
                ("record_count", len(record_tuple)),
            ),
        )
    reason = "queue_identity_failure_records_rejected"
    return QueueIdentityFailureRecordsDecision(
        records=(),
        accepted=False,
        reason=reason,
        evidence=scheduler_evidence_pairs(
            ("decision", "queue_identity_failure_records"),
            ("accepted", False),
            ("reason", reason),
            ("records_type", no_hook_type_name(records)),
        ),
    )


def queue_expected_file_count_decision(files: object) -> QueueExpectedFileCountDecision:
    if files is None:
        reason = "queue_expected_file_count_missing"
        return QueueExpectedFileCountDecision(
            count=None,
            accepted=False,
            reason=reason,
            evidence=scheduler_evidence_pairs(
                ("decision", "queue_expected_file_count"),
                ("accepted", False),
                ("reason", reason),
                ("files_type", "NoneType"),
            ),
        )
    items = no_hook_sequence_items(files)
    return QueueExpectedFileCountDecision(
        count=len(items),
        accepted=True,
        reason="queue_expected_file_count_materialized",
        evidence=scheduler_evidence_pairs(
            ("decision", "queue_expected_file_count"),
            ("accepted", True),
            ("reason", "queue_expected_file_count_materialized"),
            ("count", len(items)),
            ("files_type", no_hook_type_name(files)),
        ),
    )


__all__ = (
    "QueueExpectedFileCountDecision",
    "QueueIdentityFailureRecordsDecision",
    "queue_expected_file_count_decision",
    "queue_identity_failure_records_decision",
)
