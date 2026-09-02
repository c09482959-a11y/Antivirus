"""Publication of partial/candidate decisions from canonical chain evidence."""

from __future__ import annotations

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.no_hook_materialization import no_hook_text


def _sequence(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if type(value) in (tuple, list):
        return tuple(value)
    if type(value) in (set, frozenset):
        return tuple(sorted(value))
    if type(value) in (str, bytes, bytearray):
        return (value,)
    return ()


def high_gate_calls(api_calls: object = None) -> frozenset[str]:
    """Materialize primitive API names without owning chain policy."""
    calls: set[str] = set()
    for value in _sequence(api_calls)[:256]:
        text, reason = no_hook_text(
            value,
            missing_reason="missing_chain_api_call",
            unsupported_reason="unsafe_chain_api_call_rejected",
        )
        if not reason and text.strip():
            calls.add(text.strip().lower())
    return frozenset(calls)


def detect_strong_partial_chains(chain_evidence: ChainEvidence) -> dict[str, object]:
    """Publish weaker decisions from the exact bundle without authorizing HIGH."""
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("canonical_chain_evidence_required")
    decisions = tuple(
        decision
        for decision in chain_evidence.decisions
        if decision.status in {"candidate", "partial"}
    )
    return {
        "version": chain_evidence.registry_version,
        "registry_digest": chain_evidence.registry_digest,
        "allowed_high": False,
        "chains": tuple(decision.candidate.chain_id for decision in decisions),
        "floor": 0.0,
        "records": tuple(decision.to_record() for decision in decisions),
        "degraded": bool(chain_evidence.failures),
        "failure_evidence": tuple(dict(item) for item in chain_evidence.failures),
    }


__all__ = ("detect_strong_partial_chains", "high_gate_calls")
