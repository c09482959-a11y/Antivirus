"""Replayable typed decisions for worker retire-token boundaries."""
from __future__ import annotations

from dataclasses import dataclass


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.evidence_pairs import JsonEvidencePairs, scheduler_evidence_pairs


@dataclass(frozen=True)
class RetireTokenNameDecision:
    name: str
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


@dataclass(frozen=True)
class RetireTokenRequestDecision:
    requested: int
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


@dataclass(frozen=True)
class RetireTokenConsumeDecision:
    consumed: bool
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


def retire_token_name_decision(name: object) -> RetireTokenNameDecision:
    if type(name) is str:
        text = str.__str__(name)
        if text.endswith('.token'):
            return RetireTokenNameDecision(
                name=text,
                accepted=True,
                reason='accepted_queue_retire_token_name',
                evidence=scheduler_evidence_pairs(
                    ('decision', 'retire_token_name'),
                    ('accepted', True),
                    ('reason', 'accepted_queue_retire_token_name'),
                    ('value_type', 'str'),
                    ('name_length', len(text)),
                ),
            )
    reason = 'queue_retire_token_name_rejected'
    return RetireTokenNameDecision(
        name=str(),
        accepted=False,
        reason=reason,
        evidence=scheduler_evidence_pairs(
            ('decision', 'retire_token_name'),
            ('accepted', False),
            ('reason', reason),
            ('value_type', no_hook_type_name(name)),
        ),
    )


def retire_token_request_decision(count: int, *, reason: str) -> RetireTokenRequestDecision:
    requested = max(0, count)
    accepted = requested > 0
    decision_reason = reason or ('accepted_queue_worker_retire_count' if accepted else 'queue_worker_retire_count_zero')
    return RetireTokenRequestDecision(
        requested=requested,
        accepted=accepted,
        reason=decision_reason,
        evidence=scheduler_evidence_pairs(
            ('decision', 'retire_token_request'),
            ('accepted', accepted),
            ('reason', decision_reason),
            ('requested', requested),
        ),
    )


def retire_token_consume_decision(consumed: bool, *, reason: str, accepted: bool = True) -> RetireTokenConsumeDecision:
    return RetireTokenConsumeDecision(
        consumed=consumed is True,
        accepted=accepted,
        reason=reason,
        evidence=scheduler_evidence_pairs(
            ('decision', 'retire_token_consume'),
            ('accepted', accepted),
            ('reason', reason),
            ('consumed', consumed is True),
        ),
    )


__all__ = (
    'RetireTokenConsumeDecision',
    'RetireTokenNameDecision',
    'RetireTokenRequestDecision',
    'retire_token_consume_decision',
    'retire_token_name_decision',
    'retire_token_request_decision',
)
