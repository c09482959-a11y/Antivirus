"""Pure layered score orchestration over exact canonical evidence bundles."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from types import MappingProxyType

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.tag_evidence import distinct_positive_root_ids_for_tags
from Virus_Scan.contracts.yara_hits import YaraScanResult, canonical_yara_scan_result
from Virus_Scan.detection.contracts.probability import safe_clamp
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.full_analysis.boundaries import (
    full_analysis_float,
    full_analysis_sequence,
    full_analysis_text,
)
from Virus_Scan.detection.scoring.weighting.chain_bonus import calibrated_chain_bonus
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence
from Virus_Scan.detection.scoring.weighting.stage_enrichment import staged_enrichment_score
from Virus_Scan.detection.scoring.weighting.static_layer import compute_quick_static_layer

DetectionValue = object
DetectionSequence = Sequence[DetectionValue]
StringSet = set[str]
HitList = list[str]
LayerRecord = dict[str, DetectionValue]
LayerMap = dict[str, LayerRecord]
LayerInputResult = tuple[TagEvidence, StringSet, YaraScanResult]
WeightedScoreResult = tuple[float, int]
LayeredDetectionResult = dict[str, DetectionValue]

_WEIGHT_ITEMS = (("quick", 0.38), ("stage", 0.22), ("graph", 0.2), ("intel", 0.2))
_WEIGHTS = MappingProxyType(dict(_WEIGHT_ITEMS))
_GRAPH_TAGS = frozenset((
    "archive_member_graph",
    "cross_file_execution_graph",
    "graph_relationship_observed",
    "propagated_behavior_relationship",
))
_INTEL_TAGS = frozenset((
    "c2_beacon",
    "remote_command_channel",
    "network_exfiltration",
    "browser_credential_theft",
    "token_secret_access",
    "defender_disable",
    "shadowcopy_delete",
))
_LAYER_EVIDENCE_KINDS = frozenset({"observed", "normalized", "derived", "composite"})


def _bounded_score(score: DetectionValue) -> float:
    return safe_clamp(score, 0.0, 100.0)


def _unique_hits(hits: DetectionSequence) -> HitList:
    texts = []
    for hit in full_analysis_sequence(hits):
        text = full_analysis_text(hit)
        if text != "":
            texts.append(text)
    return sorted(set(texts))


def _layer_record(layers: DetectionValue, name: str) -> LayerRecord:
    if type(layers) is not dict:
        return {}
    layer = dict.get(layers, name)
    return layer if type(layer) is dict else {}


def _layer_score(layers: DetectionValue, name: str) -> float:
    return full_analysis_float(dict.get(_layer_record(layers, name), "score", 0.0))


def _layer_hit_values(layers: DetectionValue) -> Iterator[DetectionSequence]:
    for name, _weight in _WEIGHT_ITEMS:
        yield full_analysis_sequence(dict.get(_layer_record(layers, name), "hits", ()))


def _canonical_chain_evidence(value: object) -> ChainEvidence:
    if type(value) is not ChainEvidence:
        raise TypeError("canonical_chain_evidence_required")
    return value


def _layer_inputs(tags: object, yara_hits: object) -> LayerInputResult:
    if type(tags) is not TagEvidence:
        raise TypeError("layered_score_tag_evidence_required")
    evidence = scoreable_tag_evidence(tags, allowed_evidence_kinds=_LAYER_EVIDENCE_KINDS)
    return evidence, set(evidence.tags), canonical_yara_scan_result(yara_hits)


def _root_ids(
    tag_evidence: TagEvidence,
    tags: object,
    excluded_roots: frozenset[str] = frozenset(),
) -> frozenset[str]:
    roots = distinct_positive_root_ids_for_tags(
        tag_evidence.records,
        tags,
        allowed_evidence_kinds=_LAYER_EVIDENCE_KINDS,
    )
    return frozenset(root for root in roots if root not in excluded_roots)


def _tag_layer(
    tag_evidence: TagEvidence,
    tagset: StringSet,
    candidates: frozenset[str],
    chain_evidence: ChainEvidence,
    limit: float,
    points: float,
) -> tuple[float, HitList]:
    independent = tuple(
        record.canonical_tag_id
        for record in tag_evidence.records
        if record.is_positive_scoreable
        and record.canonical_tag_id in candidates
        and record.root_observation_id not in chain_evidence.scoreable_root_ids
    )
    roots = _root_ids(tag_evidence, candidates, chain_evidence.scoreable_root_ids)
    hits = sorted(set(tagset & candidates & set(independent)))
    return _bounded_score(min(limit, len(roots) * points)), hits


def _canonical_chain_layer(chain_evidence: ChainEvidence) -> tuple[float, HitList]:
    score, hits = calibrated_chain_bonus(chain_evidence)
    return _bounded_score(score), _unique_hits(hits)


def _stage_record(
    tag_evidence: TagEvidence,
    chain_evidence: ChainEvidence,
    previous_stage: object,
    current_stage: object,
) -> LayerRecord:
    del previous_stage  # Scheduler order is not file-observed chain evidence.
    current = full_analysis_text(current_stage, default="unknown")
    previous = "unknown"
    score, hits = staged_enrichment_score(tag_evidence, chain_evidence, current, 0.0)
    return {
        "name": "Layer 2 Stage Score",
        "score": _bounded_score(score),
        "hits": _unique_hits(hits),
        "stage": current,
        "previous_stage": previous,
    }


def _base_layers(
    tag_evidence: TagEvidence,
    tagset: StringSet,
    yara_result: YaraScanResult,
    previous_stage: object,
    current_stage: object,
    chain_evidence: ChainEvidence,
) -> LayerMap:
    quick = compute_quick_static_layer(tag_evidence, chain_evidence, yara_result)
    stage = _stage_record(tag_evidence, chain_evidence, previous_stage, current_stage)
    graph_score, graph_hits = _tag_layer(
        tag_evidence, tagset, _GRAPH_TAGS, chain_evidence, 32.0, 8.0,
    )
    intel_score, intel_hits = _tag_layer(
        tag_evidence, tagset, _INTEL_TAGS, chain_evidence, 38.0, 9.0,
    )
    chain_score, chain_hits = _canonical_chain_layer(chain_evidence)
    return {
        "quick": quick,
        "stage": stage,
        "graph": {
            "name": "Layer 3 Graph Score",
            "score": graph_score,
            "hits": graph_hits,
        },
        "intel": {
            "name": "Layer 4 Threat Intelligence",
            "score": _bounded_score(intel_score + chain_score),
            "hits": _unique_hits((*intel_hits, *chain_hits)),
        },
    }


def _weighted_score(layers: DetectionValue) -> WeightedScoreResult:
    score = sum(_layer_score(layers, name) * weight for name, weight in _WEIGHT_ITEMS)
    active_layers = sum(
        1 for name, _weight in _WEIGHT_ITEMS if _layer_score(layers, name) >= 20.0
    )
    score += 8.0 if active_layers >= 3 else 4.0 if active_layers == 2 else 0.0
    return _bounded_score(score), active_layers


def _classification_for_score(score: float) -> str:
    if score >= 75.0:
        return "malicious"
    if score >= 50.0:
        return "high_confidence"
    if score >= 25.0:
        return "low_confidence"
    return "clean"


def _layer_reasons(layers: DetectionValue) -> HitList:
    reasons = []
    for hits in _layer_hit_values(layers):
        reasons.extend(hits)
    return _unique_hits(reasons)


def _layered_result(
    score: float,
    active_layers: int,
    layers: LayerMap,
    evidence: ChainEvidence,
    tag_evidence: TagEvidence,
    tagset: StringSet,
    yara_result: YaraScanResult,
) -> LayeredDetectionResult:
    all_roots = _root_ids(tag_evidence, tagset)
    return {
        "score": score,
        "classification": _classification_for_score(score),
        "reasons": _layer_reasons(layers),
        "attack_family": None,
        "family_probabilities": {},
        "layers": layers,
        "active_layers": active_layers,
        "weights": _WEIGHTS,
        "anchor_chain_high_gate": {},
        "renpy_failsafe_cap": None,
        "score_breakdown": {
            "immutable_evidence_tags": len(all_roots),
            "immutable_evidence_roots": len(all_roots),
            "canonical_tag_count": len(tagset),
            "canonical_chain_family_count": len(evidence.scoreable_families),
            "canonical_chain_score_points": evidence.total_score_points,
            "yara_hit_count": yara_result.retained_match_count,
            "yara_scan_status": yara_result.status,
        },
    }


def compute_layered_detection(
    node: DetectionValue,
    tags: TagEvidence,
    chain_evidence: ChainEvidence,
    yara_hits: DetectionValue = None,
    prev_stage: DetectionValue = None,
    curr_stage: DetectionValue = None,
    ordered_events: DetectionValue = None,
) -> LayeredDetectionResult:
    """Calculate pre-cap layers from exact immutable evidence bundles."""
    del node, ordered_events
    evidence = _canonical_chain_evidence(chain_evidence)
    tag_evidence, tagset, yara_result = _layer_inputs(tags, yara_hits)
    layers = _base_layers(
        tag_evidence,
        tagset,
        yara_result,
        prev_stage,
        curr_stage,
        evidence,
    )
    score, active_layers = _weighted_score(layers)
    return _layered_result(
        score,
        active_layers,
        layers,
        evidence,
        tag_evidence,
        tagset,
        yara_result,
    )


__all__ = ("compute_layered_detection",)
