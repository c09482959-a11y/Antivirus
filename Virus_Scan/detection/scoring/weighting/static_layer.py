"""Canonical quick-static score over independent atomic evidence roots."""

from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.yara_hits import canonical_yara_scan_result
from Virus_Scan.contracts.tag_evidence import TagEvidenceRecord
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence

_STATIC_EVIDENCE_KINDS = frozenset({"observed", "normalized", "derived", "composite"})
_STATIC_POINT_ROWS = (
    ("amsi_scanbuffer_patch", 18.0),
    ("etw_eventwrite_patch", 18.0),
    ("local_admin_add", 18.0),
    ("admin_user_creation", 16.0),
    ("mimikatz_credential_dump", 18.0),
    ("high_confidence_credential_theft", 20.0),
    ("high_confidence_browser_credential_theft", 20.0),
    ("memory_write", 7.0),
    ("thread_execution", 7.0),
    ("memory_allocate", 5.0),
    ("encoded_powershell", 9.0),
    ("powershell_exec", 7.0),
    ("payload_decode_candidate", 6.0),
    ("script_execution", 6.0),
    ("process_exec", 6.0),
    ("dpapi_access", 5.0),
    ("browser_profile_access", 5.0),
    ("token_secret_access", 6.0),
    ("network_download", 4.0),
    ("packed_or_obfuscated", 8.0),
    ("keylogging_behavior", 8.0),
    ("clipboard_access", 5.0),
    ("service_create", 9.0),
    ("service_persistence", 9.0),
    ("screenshot_capture", 6.0),
    ("admin_share_access", 7.0),
    ("defender_disable", 8.0),
    ("shadowcopy_delete", 8.0),
    ("certutil_exec", 8.0),
    ("credential_dump_attempt", 10.0),
    ("lsass_access", 10.0),
    ("network_exfiltration", 10.0),
    ("fileless_execution", 8.0),
    ("mshta_exec", 8.0),
    ("regsvr32_exec", 8.0),
    ("rundll32_exec", 7.0),
    ("bitsadmin_exec", 8.0),
)
_STATIC_POINTS = MappingProxyType(dict(_STATIC_POINT_ROWS))


def _canonical_inputs(
    tags: object,
    chain_evidence: object,
) -> tuple[TagEvidence, ChainEvidence]:
    if type(tags) is not TagEvidence:
        raise TypeError("quick_static_tag_evidence_required")
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("quick_static_chain_evidence_required")
    evidence = scoreable_tag_evidence(tags, allowed_evidence_kinds=_STATIC_EVIDENCE_KINDS)
    return evidence, chain_evidence


def _independent_records(
    evidence: TagEvidence,
    chain_evidence: ChainEvidence,
) -> tuple[TagEvidenceRecord, ...]:
    records = tuple(
        record
        for record in evidence.records
        if record.is_positive_scoreable
        and record.evidence_kind in _STATIC_EVIDENCE_KINDS
        and record.root_observation_id not in chain_evidence.scoreable_root_ids
    )
    return tuple(sorted(records, key=lambda item: (
        item.root_observation_id,
        item.canonical_tag_id,
        item.evidence_id,
    )))


def _atomic_static_score(
    records: tuple[TagEvidenceRecord, ...],
) -> tuple[float, list[str]]:
    root_best: dict[str, tuple[float, str]] = {}
    for record in records:
        points = _STATIC_POINTS.get(record.canonical_tag_id, 0.0)
        candidate = (points, record.canonical_tag_id)
        current = root_best.get(record.root_observation_id)
        if points > 0.0 and (current is None or candidate > current):
            root_best[record.root_observation_id] = candidate
    score = min(48.0, sum(points for points, _tag in root_best.values()))
    hits = sorted({"static_observation:" + tag for _points, tag in root_best.values()})
    return score, hits


def compute_quick_static_layer(
    tags: TagEvidence,
    chain_evidence: ChainEvidence,
    yara_hits: object = None,
) -> dict[str, object]:
    """Score atomic roots once; canonical chains own multi-signal policy."""
    evidence, canonical_chains = _canonical_inputs(tags, chain_evidence)
    score, hits = _atomic_static_score(_independent_records(evidence, canonical_chains))
    yara_degraded = False
    yara_unavailable_reason = ""
    if yara_hits is not None:
        yara_result = canonical_yara_scan_result(yara_hits)
        yara_degraded = yara_result.status in {"unavailable", "failed", "partial", "truncated"}
        if yara_degraded:
            hits.append("yara_static_evidence_degraded")
            yara_unavailable_reason = yara_result.unavailable_reason or yara_result.status
    result: dict[str, object] = {
        "name": "Layer 1 Quick Score",
        "score": min(100.0, score),
        "hits": sorted(set(hits)),
        "summary": "independent atomic static evidence",
        "scanner_degraded": yara_degraded,
        "yara_unavailable_reason": yara_unavailable_reason or None,
    }
    return result


__all__ = ("compute_quick_static_layer",)
