"""Replayable typed decisions for failed-queue diagnostic repair boundaries."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items_status,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.scheduler.evidence_pairs import JsonEvidencePairs, scheduler_evidence_pairs
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items


@dataclass(frozen=True)
class FailedQueueNameDecision:
    text: str
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


@dataclass(frozen=True)
class FailedQueueMappingDecision:
    mapping: dict[str, object]
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


@dataclass(frozen=True)
class FailedQueueRepairCountDecision:
    count: int
    reason: str
    evidence: JsonEvidencePairs


def failed_queue_name_decision(value: object) -> FailedQueueNameDecision:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_failed_queue_name",
        unsupported_reason="unsafe_failed_queue_name_rejected",
    )
    accepted = reason == "" and text != ""
    decision_text = text if accepted else ""
    decision_reason = "accepted_failed_queue_name" if accepted else reason or "empty_failed_queue_name"
    return FailedQueueNameDecision(
        text=decision_text,
        accepted=accepted,
        reason=decision_reason,
        evidence=scheduler_evidence_pairs(
            ("decision", "failed_queue_name"),
            ("accepted", accepted),
            ("reason", decision_reason),
            ("value_type", no_hook_type_name(value)),
        ),
    )


def failed_queue_mapping_decision(value: object) -> FailedQueueMappingDecision:
    items, reason = no_hook_mapping_items_status(value, allow_dict_subclass=True)
    if items is None:
        decision_reason = reason or "failed_queue_mapping_unavailable"
        return FailedQueueMappingDecision(
            mapping={},
            accepted=False,
            reason=decision_reason,
            evidence=scheduler_evidence_pairs(
                ("decision", "failed_queue_mapping"),
                ("accepted", False),
                ("reason", decision_reason),
                ("value_type", no_hook_type_name(value)),
            ),
        )
    filtered = scheduler_str_key_mapping_from_items(items)
    rejected_keys = len(items) - len(filtered)
    decision_reason = "accepted_failed_queue_mapping" if rejected_keys == 0 else "non_text_failed_queue_mapping_keys_rejected"
    return FailedQueueMappingDecision(
        mapping=filtered,
        accepted=True,
        reason=decision_reason,
        evidence=scheduler_evidence_pairs(
            ("decision", "failed_queue_mapping"),
            ("accepted", True),
            ("reason", decision_reason),
            ("value_type", no_hook_type_name(value)),
            ("accepted_keys", len(filtered)),
            ("rejected_keys", rejected_keys),
        ),
    )


def failed_queue_repair_count_decision(count: int, *, reason: str) -> FailedQueueRepairCountDecision:
    safe_count = count if type(count) is int and type(count) is not bool and count >= 0 else 0
    decision_reason = reason if type(reason) is str and reason else "failed_queue_repair_count_recorded"
    return FailedQueueRepairCountDecision(
        count=safe_count,
        reason=decision_reason,
        evidence=scheduler_evidence_pairs(
            ("decision", "failed_queue_repair_count"),
            ("count", safe_count),
            ("reason", decision_reason),
        ),
    )


__all__ = (
    "FailedQueueMappingDecision",
    "FailedQueueNameDecision",
    "FailedQueueRepairCountDecision",
    "failed_queue_mapping_decision",
    "failed_queue_name_decision",
    "failed_queue_repair_count_decision",
)
