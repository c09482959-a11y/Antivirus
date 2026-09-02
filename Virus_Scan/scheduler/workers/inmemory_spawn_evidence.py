"""Replayable typed decisions for in-memory worker respawn boundaries."""
from __future__ import annotations

from dataclasses import dataclass


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.evidence_pairs import JsonEvidencePairs, scheduler_evidence_pairs
from Virus_Scan.scheduler.internal.no_hook_methods import safe_scheduler_bound_method


@dataclass(frozen=True)
class InMemoryOwnedNonemptyDecision:
    nonempty: bool
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


@dataclass(frozen=True)
class InMemoryProcessAliveDecision:
    alive: bool
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


def inmemory_owned_nonempty_decision(value: object, *, field_name: str) -> InMemoryOwnedNonemptyDecision:
    if value is None:
        reason = "missing_" + field_name + "_empty"
        return InMemoryOwnedNonemptyDecision(
            nonempty=bool(()),
            accepted=True,
            reason=reason,
            evidence=scheduler_evidence_pairs(
                ("decision", "inmemory_owned_nonempty"),
                ("field_name", field_name),
                ("accepted", True),
                ("reason", reason),
                ("value_type", "NoneType"),
                ("item_count", 0),
            ),
        )
    if type(value) in (tuple, list, set, frozenset, dict):
        item_count = len(value)
        return InMemoryOwnedNonemptyDecision(
            nonempty=item_count > 0,
            accepted=True,
            reason="accepted_" + field_name,
            evidence=scheduler_evidence_pairs(
                ("decision", "inmemory_owned_nonempty"),
                ("field_name", field_name),
                ("accepted", True),
                ("reason", "accepted_" + field_name),
                ("value_type", no_hook_type_name(value)),
                ("item_count", item_count),
            ),
        )
    reason = "unsafe_" + field_name + "_rejected"
    return InMemoryOwnedNonemptyDecision(
        nonempty=bool(()),
        accepted=False,
        reason=reason,
        evidence=scheduler_evidence_pairs(
            ("decision", "inmemory_owned_nonempty"),
            ("field_name", field_name),
            ("accepted", False),
            ("reason", reason),
            ("value_type", no_hook_type_name(value)),
        ),
    )


def inmemory_process_alive_decision(proc: object) -> InMemoryProcessAliveDecision:
    alive_method, reason = safe_scheduler_bound_method(
        proc,
        "is_alive",
        reason_prefix="unsafe_inmemory_respawn_process",
    )
    if reason or alive_method is None:
        decision_reason = reason or "missing_inmemory_respawn_is_alive"
        return InMemoryProcessAliveDecision(
            alive=bool(()),
            accepted=False,
            reason=decision_reason,
            evidence=scheduler_evidence_pairs(
                ("decision", "inmemory_process_alive"),
                ("accepted", False),
                ("reason", decision_reason),
                ("value_type", no_hook_type_name(proc)),
            ),
        )
    alive = alive_method() is True
    return InMemoryProcessAliveDecision(
        alive=alive,
        accepted=True,
        reason="accepted_inmemory_process_alive",
        evidence=scheduler_evidence_pairs(
            ("decision", "inmemory_process_alive"),
            ("accepted", True),
            ("reason", "accepted_inmemory_process_alive"),
            ("value_type", no_hook_type_name(proc)),
            ("alive", alive),
        ),
    )


__all__ = (
    "InMemoryOwnedNonemptyDecision",
    "InMemoryProcessAliveDecision",
    "inmemory_owned_nonempty_decision",
    "inmemory_process_alive_decision",
)
