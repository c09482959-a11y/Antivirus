"""API, graph, model, evidence, and cluster context owners."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import compute_attack_intelligence
from Virus_Scan.detection.evidence.behavioral.semantics import tag_evidence_provenance_report
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.models.enriched_stage_outputs import DetectionEvidenceFacts
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.models.failure_state import DetectionFailureState
from Virus_Scan.detection.evidence.failure_evidence import recoverable_failure_evidence
from Virus_Scan.detection.tags.evidence_generation import (
    finalize_tag_evidence_generation,
    merge_tag_evidence_inputs,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.tags.heuristics.family_heuristics import enhanced_family_heuristics
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_set
from Virus_Scan.detection.tags.process.api_tags import infer_observations_from_api
from Virus_Scan.detection.enrichment.full_analysis.api_graph_context import (
    build_behavior_timeline,
    enrich_with_api_and_graph,
)
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.detection.enrichment.full_analysis.boundaries import (
    fa_list,
    fa_mapping,
    fa_mapping_get,
    fa_sequence,
    fa_text,
)


DetectionValue = object
DetectionMapping = dict[str, DetectionValue]
DetectionReadMapping = Mapping[str, DetectionValue]
DetectionSequence = Sequence[DetectionValue]
StageFailureRecords = list[DetectionValue]
ApiEnrichmentResult = tuple[TagEvidence, DetectionMapping, list[DetectionValue], list[DetectionValue]]
DetectionArtifactMap = dict[str, DetectionValue]
ApiGraphEnricher = Callable[..., DetectionValue]
FamilyHeuristicsBuilder = Callable[..., DetectionValue]


def _empty_api_graph_result() -> DetectionMapping:
    return {
        "api_calls": [],
        "ngrams": [],
        "call_graph": {},
        "graph_features": {},
        "behavior_timeline": [],
        "ordered_events": [],
    }


def _append_recoverable_failure(
    stage_failures: StageFailureRecords,
    *,
    stage_name: str,
    error: BaseException | str,
    error_source: str,
    affected_context: DetectionValue,
) -> DetectionFailureState:
    failure = recoverable_failure_evidence(
        stage_name=stage_name,
        error=error,
        error_source=error_source,
        affected_context=affected_context,
    )
    stage_failures.append(failure)
    return failure


def _degraded_api_enrichment(
    *,
    tags: DetectionValue,
    strings_blob: str,
    failure: DetectionFailureState,
) -> ApiEnrichmentResult:
    tag_evidence = (
        tags if type(tags) is TagEvidence else normalize_tag_evidence(
            tags, source_detector='api_graph_enrichment', source_stage='degraded_input',
        )
    )
    behavior_timeline, ordered_events = build_behavior_timeline(
        strings_blob=strings_blob, api_calls=[], api_sequence=[], tags=tag_evidence.tags,
    )
    api_result = _empty_api_graph_result()
    api_result["degraded"] = True
    api_result["degraded_stage"] = "api_graph_enrichment"
    api_result["failure_evidence"] = [failure.to_record()]
    api_result["final_json_must_record"] = True
    api_result["replay_record_required"] = True
    return tag_evidence, api_result, behavior_timeline, ordered_events


def _api_tag_evidence(path: DetectionValue, api_result: DetectionMapping) -> TagEvidence:
    path_text = str.__str__(path).strip() if type(path) is str else ""
    observations = infer_observations_from_api(
        fa_list(fa_mapping_get(api_result, "api_calls", ())),
        artifact_identity=("path:" + path_text) if path_text else "",
        producer_id="api_call_classifier",
    )
    return normalize_tag_evidence(
        observations,
        source_detector="api_call_classifier",
        source_stage="api_classification",
    )


_API_SEQUENCE_FIELDS = (
    "api_calls", "api_tags", "string_tags", "sequence", "behavior_timeline",
    "ordered_events", "ngrams",
)
_API_MAPPING_FIELDS = ("call_graph", "graph_features")


def _detach_api_result(result: DetectionValue) -> DetectionMapping:
    detached = fa_mapping(result)
    for field in _API_SEQUENCE_FIELDS:
        if field in detached:
            detached[field] = fa_sequence(detached[field])
    for field in _API_MAPPING_FIELDS:
        if field in detached:
            detached[field] = fa_mapping(detached[field])
    return detached


def _run_api_enricher(
    *, path: DetectionValue, strings_blob: str, tags: DetectionValue,
    strings_already_enriched: DetectionValue, api_graph_enricher: ApiGraphEnricher,
) -> tuple[TagEvidence, DetectionMapping]:
    base = tags if type(tags) is TagEvidence else finalize_tag_evidence_generation(
        tags, path=path, strings_blob=strings_blob, source="api_precomputed_generation",
    ).evidence
    result = api_graph_enricher(
        path, strings_blob, [],
        strings_already_enriched=strings_already_enriched,
        precomputed_tags=list(base.tags),
    )
    return base, _detach_api_result(result)


def _build_api_enrichment_context(
    *, path: DetectionValue, tags: DetectionValue, strings_blob: str,
    strings_already_enriched: DetectionValue, api_graph_enricher: ApiGraphEnricher,
    stage_failures: StageFailureRecords,
) -> ApiEnrichmentResult:
    try:
        base_evidence, api_result = _run_api_enricher(
            path=path, strings_blob=strings_blob, tags=tags,
            strings_already_enriched=strings_already_enriched,
            api_graph_enricher=api_graph_enricher,
        )
        api_evidence = _api_tag_evidence(path, api_result)
        merged_evidence = merge_tag_evidence_inputs((base_evidence, api_evidence))
        tag_evidence = finalize_tag_evidence_generation(
            merged_evidence, path=path, strings_blob=strings_blob,
            source="api_enrichment",
        ).evidence
        behavior_timeline, ordered_events = build_behavior_timeline(
            strings_blob=strings_blob,
            api_calls=fa_list(fa_mapping_get(api_result, "api_calls", ())),
            api_sequence=fa_list(fa_mapping_get(api_result, "sequence", ())),
            tags=tag_evidence.tags,
        )
        api_result["behavior_timeline"] = behavior_timeline
        api_result["ordered_events"] = ordered_events
        return tag_evidence, api_result, behavior_timeline, ordered_events
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        failure = _append_recoverable_failure(
            stage_failures,
            stage_name="api_graph_enrichment",
            error=error,
            error_source="enrich_with_api_and_graph",
            affected_context=path,
        )
        return _degraded_api_enrichment(tags=tags, strings_blob=strings_blob, failure=failure)

def _build_attack_info(
    *,
    tag_evidence: TagEvidence,
    yara_evidence: DetectionValue,
    strings_blob: str,
    path: DetectionValue,
    stage_failures: StageFailureRecords,
) -> DetectionMapping:
    try:
        return compute_attack_intelligence(
            tag_evidence,
            yara_evidence,
            strings_blob=strings_blob,
        )
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        failure = _append_recoverable_failure(
            stage_failures,
            stage_name="attack_intelligence",
            error=error,
            error_source="compute_attack_intelligence",
            affected_context=path,
        )
        return {"failure_evidence": [failure.to_record()]}


def _build_evidence_provenance(
    *,
    tags: DetectionSequence,
    strings_blob: str,
    path: DetectionValue,
    api_result: DetectionReadMapping,
    ordered_events: DetectionSequence,
    stage_failures: StageFailureRecords,
) -> DetectionMapping:
    try:
        return tag_evidence_provenance_report(
            tags,
            strings_blob=strings_blob,
            path=path,
            api_calls=fa_list(fa_mapping_get(api_result, "api_calls", ())),
            ordered_events=fa_list(ordered_events),
        )
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        failure = _append_recoverable_failure(
            stage_failures,
            stage_name="evidence_provenance",
            error=error,
            error_source="tag_evidence_provenance_report",
            affected_context=path,
        )
        return {"error": str(error), "failure_evidence": [failure.to_record()]}


def _build_family_heuristics(
    *,
    family_heuristics_builder: FamilyHeuristicsBuilder,
    path: DetectionValue,
    tags: DetectionSequence,
    strings_blob: str,
    api_result: DetectionReadMapping,
    stage_failures: StageFailureRecords,
) -> DetectionMapping:
    try:
        family_tags = tags.tags if type(tags) is TagEvidence else tags
        return family_heuristics_builder(
            path=path,
            tags=family_tags,
            strings_blob=strings_blob,
            api_calls=fa_list(fa_mapping_get(api_result, "api_calls", ())),
        )
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        failure = _append_recoverable_failure(
            stage_failures,
            stage_name="family_heuristics",
            error=error,
            error_source="enhanced_family_heuristics",
            affected_context=path,
        )
        return {"score": 0.0, "hits": [], "failure_evidence": [failure.to_record()]}


def _build_chain_evidence(
    *,
    tag_evidence: TagEvidence,
    api_result: DetectionReadMapping,
    ordered_events: DetectionSequence,
    static_program_analyses: object,
) -> ChainEvidence:
    return evaluate_chain_evidence(
        tags=tag_evidence,
        api_calls=fa_list(fa_mapping_get(api_result, "api_calls", ())),
        ordered_events=fa_list(ordered_events),
        static_program_analyses=static_program_analyses,
    )


def build_detection_api_context(
    *, path: DetectionValue, tags: DetectionValue, yara_evidence: DetectionValue = None,
    strings_blob: DetectionValue, strings_already_enriched: DetectionValue,
    static_program_analyses: DetectionValue = (), failure_evidence: DetectionValue = (),
    api_graph_enricher: ApiGraphEnricher = enrich_with_api_and_graph,
    family_heuristics_builder: FamilyHeuristicsBuilder = enhanced_family_heuristics,
) -> DetectionEvidenceFacts:
    """Build authoritative enrichment and ChainEvidence before model context exists."""
    stage_failures = fa_list(failure_evidence)
    tags = tags if type(tags) is TagEvidence else fa_list(tags)
    strings_blob = fa_text(strings_blob)
    tag_evidence, api_result, behavior_timeline, ordered_events = _build_api_enrichment_context(
        path=path, tags=tags, strings_blob=strings_blob,
        strings_already_enriched=strings_already_enriched,
        api_graph_enricher=api_graph_enricher, stage_failures=stage_failures,
    )
    chain_evidence = _build_chain_evidence(
        tag_evidence=tag_evidence, api_result=api_result, ordered_events=ordered_events,
        static_program_analyses=static_program_analyses,
    )
    attack_info = _build_attack_info(
        tag_evidence=tag_evidence, yara_evidence=yara_evidence, strings_blob=strings_blob,
        path=path, stage_failures=stage_failures,
    )
    evidence_provenance = _build_evidence_provenance(
        tags=tag_evidence, strings_blob=strings_blob, path=path, api_result=api_result,
        ordered_events=ordered_events, stage_failures=stage_failures,
    )
    heur = _build_family_heuristics(
        family_heuristics_builder=family_heuristics_builder, path=path, tags=tag_evidence,
        strings_blob=strings_blob, api_result=api_result, stage_failures=stage_failures,
    )
    return DetectionEvidenceFacts(
        api_result=api_result, behavior_timeline=tuple(behavior_timeline),
        ordered_events=tuple(ordered_events), tag_evidence=tag_evidence, chain_evidence=chain_evidence,
        attack_info=attack_info, baseline_maturity={}, evidence_provenance=evidence_provenance,
        heur=heur, failure_evidence=tuple(stage_failures),
    )
