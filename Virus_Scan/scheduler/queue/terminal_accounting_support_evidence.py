"""Replayable typed decisions for queue terminal accounting support boundaries."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_type_name
from Virus_Scan.scheduler.evidence_pairs import JsonEvidencePairs, scheduler_evidence_pairs


@dataclass(frozen=True)
class TerminalAccountingSequenceDecision:
    items: tuple[object, ...]
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


@dataclass(frozen=True)
class TerminalAccountingDurableResultsDecision:
    results: dict[str, object]
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


def terminal_accounting_sequence_decision(
    value: object,
    *,
    field_name: str,
    rejection_reason: str,
) -> TerminalAccountingSequenceDecision:
    if type(value) not in (tuple, list):
        reason = rejection_reason if type(rejection_reason) is str and rejection_reason else "queue_terminal_sequence_rejected"
        return TerminalAccountingSequenceDecision(
            items=(),
            accepted=False,
            reason=reason,
            evidence=scheduler_evidence_pairs(
                ("decision", "terminal_accounting_sequence"),
                ("field_name", field_name),
                ("accepted", False),
                ("reason", reason),
                ("value_type", no_hook_type_name(value)),
            ),
        )
    items = no_hook_sequence_items(value)
    return TerminalAccountingSequenceDecision(
        items=items,
        accepted=True,
        reason="accepted_terminal_accounting_sequence",
        evidence=scheduler_evidence_pairs(
            ("decision", "terminal_accounting_sequence"),
            ("field_name", field_name),
            ("accepted", True),
            ("reason", "accepted_terminal_accounting_sequence"),
            ("value_type", no_hook_type_name(value)),
            ("item_count", len(items)),
        ),
    )


def durable_results_decision(
    value: object,
    *,
    materialized: object,
    reason: str,
) -> TerminalAccountingDurableResultsDecision:
    accepted = type(materialized) is dict
    safe_reason = reason if type(reason) is str and reason else "queue_durable_results_decision_recorded"
    results = dict(materialized) if accepted else {}
    return TerminalAccountingDurableResultsDecision(
        results=results,
        accepted=accepted,
        reason=safe_reason,
        evidence=scheduler_evidence_pairs(
            ("decision", "terminal_accounting_durable_results"),
            ("accepted", accepted),
            ("reason", safe_reason),
            ("value_type", no_hook_type_name(value)),
            ("result_count", len(results)),
        ),
    )


__all__ = (
    "TerminalAccountingDurableResultsDecision",
    "TerminalAccountingSequenceDecision",
    "durable_results_decision",
    "terminal_accounting_sequence_decision",
)
