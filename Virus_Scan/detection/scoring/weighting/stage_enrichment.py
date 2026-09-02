"""Canonical stage-specific scoring over evidence not consumed by chains.

The stage layer never owns multi-signal behavior policy. Canonical chain rules
own those relationships. This module scores only independent stage observations
whose root evidence is not already consumed by a scoreable chain decision.
"""

from __future__ import annotations

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text
from Virus_Scan.contracts.tag_evidence import TagEvidenceRecord
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.weighting.chain_bonus import cap_noise_only_score
from Virus_Scan.detection.scoring.weighting.policy_constants import STAGE_WEIGHT
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence

_STAGE_EVIDENCE_KINDS = frozenset({"observed", "normalized", "derived", "composite"})
_STAGE_POINT_ROWS = (
    ("*", "network_c2", 10.0),
    ("*", "remote_command_channel", 12.0),
    ("*", "network_exfiltration", 10.0),
    ("*", "token_exfiltration", 10.0),
    ("*", "token_secret_access", 9.0),
    ("*", "browser_credential_access", 9.0),
    ("*", "browser_storage_access", 8.0),
    ("*", "credential_dump_attempt", 10.0),
    ("*", "process_injection", 10.0),
    ("*", "persistence", 8.0),
    ("*", "service_persistence", 9.0),
    ("*", "defender_disable", 10.0),
    ("*", "shadowcopy_delete", 10.0),
    ("*", "process_exec", 6.0),
    ("*", "script_execution", 6.0),
    ("*", "network_download", 6.0),
    ("*", "payload_decode_candidate", 5.0),
    ("*", "embedded_pe_signature_found", 8.0),
    ("runtime", "dynamic_execution", 6.0),
    ("runtime", "clipboard_access", 5.0),
    ("runtime", "keylogging_behavior", 8.0),
    ("cs", "assembly_load", 6.0),
    ("cs", "reflection_dotnet", 8.0),
    ("binary", "memory_allocate", 5.0),
    ("binary", "memory_write", 6.0),
    ("binary", "thread_execution", 6.0),
    ("asset", "image_payload_confirmed", 10.0),
    ("image", "image_payload_confirmed", 10.0),
    ("archive", "archive_dropper", 10.0),
)


def _stage_text(value: object, default: str = "unknown") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_stage_text",
        unsupported_reason="unsafe_stage_text_rejected",
    )
    return default if reason or text == "" else str.lower(text)


def _stage_float(value: object, default: float = 0.0) -> float:
    metric, _reason = no_hook_finite_float(
        value,
        default=default,
        reason="unsafe_stage_numeric_value_rejected",
        non_finite_reason="non_finite_stage_numeric_value",
        allow_exact_text=True,
    )
    return float(metric)


def _canonical_inputs(tags: object, chain_evidence: object) -> tuple[TagEvidence, ChainEvidence]:
    if type(tags) is not TagEvidence:
        raise TypeError("stage_tag_evidence_required")
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("stage_chain_evidence_required")
    evidence = scoreable_tag_evidence(tags, allowed_evidence_kinds=_STAGE_EVIDENCE_KINDS)
    return evidence, chain_evidence



def _stage_points(stage: str, tag: str) -> float:
    return max(
        (points for policy_stage, policy_tag, points in _STAGE_POINT_ROWS
         if policy_tag == tag and policy_stage in {"*", stage}),
        default=0.0,
    )


def _independent_root_records(
    evidence: TagEvidence,
    chain_evidence: ChainEvidence,
) -> tuple[TagEvidenceRecord, ...]:
    consumed = chain_evidence.scoreable_root_ids
    records = tuple(
        record for record in evidence.records
        if record.is_positive_scoreable
        and record.evidence_kind in _STAGE_EVIDENCE_KINDS
        and record.root_observation_id not in consumed
    )
    return tuple(sorted(records, key=lambda item: (
        item.root_observation_id, item.canonical_tag_id, item.evidence_id,
    )))


def _independent_stage_score(
    records: tuple[TagEvidenceRecord, ...],
    stage: str,
) -> tuple[float, list[str]]:
    root_best: dict[str, tuple[float, str]] = {}
    for record in records:
        points = _stage_points(stage, record.canonical_tag_id)
        if points <= 0.0:
            continue
        current = root_best.get(record.root_observation_id)
        candidate = (points, record.canonical_tag_id)
        if current is None or candidate > current:
            root_best[record.root_observation_id] = candidate
    score = sum(points for points, _tag in root_best.values())
    hits = ["stage_observation:" + tag for _points, tag in root_best.values()]
    return score, sorted(set(hits))


def staged_enrichment_score(
    tags: TagEvidence,
    chain_evidence: ChainEvidence,
    stage: object,
    asset_score: object = 0.0,
) -> tuple[float, list[str]]:
    """Score independent stage observations without re-scoring chain roots."""
    evidence, canonical_chains = _canonical_inputs(tags, chain_evidence)
    canonical_stage = _stage_text(stage)
    score, hits = _independent_stage_score(
        _independent_root_records(evidence, canonical_chains), canonical_stage,
    )
    score += _stage_float(asset_score)
    if canonical_chains.failures:
        hits.append("stage_chain_evidence_degraded")
    score = cap_noise_only_score(score, evidence, canonical_stage)
    weighted = min(60.0, score * STAGE_WEIGHT.get(canonical_stage, 1.0))
    return weighted, sorted(set(hits))


__all__ = ("staged_enrichment_score",)
