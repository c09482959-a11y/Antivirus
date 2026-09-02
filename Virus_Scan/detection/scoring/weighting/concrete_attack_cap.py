"""No-concrete-attack score cap over the canonical chain bundle."""

from __future__ import annotations

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float
from Virus_Scan.detection.chains.composite.attack_authority import has_concrete_attack_chain
from Virus_Scan.detection.contracts.path_predicates import binary_ext_for_attack_cap


def _cap_score_value(score: object) -> float:
    value, _reason = no_hook_finite_float(
        score,
        default=0.0,
        reason="no_concrete_attack_cap_score_rejected",
        non_finite_reason="no_concrete_attack_cap_score_non_finite",
        allow_exact_text=True,
    )
    return value


def apply_no_concrete_attack_cap(
    score: object,
    chain_evidence: ChainEvidence,
    *,
    path: object = None,
) -> object:
    """Cap binary PE risk when the exact bundle lacks concrete authority."""
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("canonical_chain_evidence_required")
    score_value = _cap_score_value(score)
    if not binary_ext_for_attack_cap(path):
        return score_value, None
    if has_concrete_attack_chain(chain_evidence):
        return score_value, None
    cap_value = 60.0
    if score_value <= cap_value:
        return score_value, None
    return cap_value, {
        "name": "no_concrete_attack_binary_cap",
        "old_score": score_value,
        "new_score": cap_value,
        "reason": "binary_or_pe_evidence_without_concrete_attack_chain",
        "chain_registry_version": chain_evidence.registry_version,
        "chain_registry_digest": chain_evidence.registry_digest,
    }


__all__ = ("apply_no_concrete_attack_cap",)
