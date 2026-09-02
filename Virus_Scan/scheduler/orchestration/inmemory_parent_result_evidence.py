"""Replayable typed decisions for in-memory parent result-message handling."""
from __future__ import annotations

from dataclasses import dataclass


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.evidence_pairs import JsonEvidencePairs, scheduler_evidence_pairs


@dataclass(frozen=True)
class ParentResultMessageDecision:
    is_parent_result: bool
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


@dataclass(frozen=True)
class ParentResultContinueDecision:
    should_continue: bool
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


def parent_result_message_decision(message: object) -> ParentResultMessageDecision:
    if type(message) not in {list, tuple}:
        reason = "parent_result_message_type_rejected"
        return ParentResultMessageDecision(
            is_parent_result=bool(()),
            accepted=False,
            reason=reason,
            evidence=scheduler_evidence_pairs(
                ("decision", "parent_result_message"),
                ("accepted", False),
                ("reason", reason),
                ("value_type", no_hook_type_name(message)),
            ),
        )
    item_count = len(message)
    if item_count < 1:
        reason = "parent_result_message_empty"
        return ParentResultMessageDecision(
            is_parent_result=bool(()),
            accepted=False,
            reason=reason,
            evidence=scheduler_evidence_pairs(
                ("decision", "parent_result_message"),
                ("accepted", False),
                ("reason", reason),
                ("value_type", no_hook_type_name(message)),
                ("item_count", item_count),
            ),
        )
    reason = "accepted_parent_result_message"
    return ParentResultMessageDecision(
        is_parent_result=True,
        accepted=True,
        reason=reason,
        evidence=scheduler_evidence_pairs(
            ("decision", "parent_result_message"),
            ("accepted", True),
            ("reason", reason),
            ("value_type", no_hook_type_name(message)),
            ("item_count", item_count),
        ),
    )


def parent_result_continue_decision(*, should_continue: bool, accepted: bool, reason: str) -> ParentResultContinueDecision:
    projected = should_continue is True
    return ParentResultContinueDecision(
        should_continue=projected,
        accepted=accepted,
        reason=reason,
        evidence=scheduler_evidence_pairs(
            ("decision", "parent_result_continue"),
            ("accepted", accepted),
            ("reason", reason),
            ("should_continue", projected),
        ),
    )


__all__ = (
    "ParentResultContinueDecision",
    "ParentResultMessageDecision",
    "parent_result_continue_decision",
    "parent_result_message_decision",
)
