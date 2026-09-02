"""Canonical extension scan routing pipeline."""
from __future__ import annotations

import os

from Virus_Scan.contracts.artifact_read_snapshot import require_artifact_read_snapshot
from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot
from Virus_Scan.contracts.detection_observation import artifact_observations_for_path_tags
from Virus_Scan.contracts.static_program_analysis import project_static_operation_observations
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items, no_hook_text, no_hook_type_name
from Virus_Scan.detection.api.routing_contracts import (
    TagEvidenceGeneration,
    emit_stage_event,
    finalize_tag_evidence_generation,
    merge_tag_evidence_inputs,
    remember_scan_evidence as _remember_scan_evidence,
    staged_enrichment_score,
    validate_tag_evidence_input_for_path,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.detection.api.tag_evidence_contracts import scoreable_tag_evidence
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.routing.graph_model_projection import route_archive_members_to_graph, route_cs_graph_tags
from Virus_Scan.routing.extension_outcome import RouteScanOutcome
from Virus_Scan.routing.extension_scan_handlers import (
    route_asset_stage,
    route_binary_stage,
    route_image_stage,
    route_other_stage,
    route_runtime_stage,
)
from Virus_Scan.routing.magic import sniff_file_identity_from_snapshot
from Virus_Scan.routing.passive_assets import _is_terminal_clean_asset_triage
from Virus_Scan.routing.static_analysis_summary import (
    build_static_analysis_summary,
    empty_static_analysis_summary,
)
from Virus_Scan.routing.scanner_execution_plan import (
    ScannerExecutionPlan,
    build_scanner_execution_plan,
    scanner_result_status,
)
from Virus_Scan.runtime.api import (
    has_any_tag,
    log_error,
    record_detector_error,
    record_suppressed_failure,
    report_scan_stage_progress,
)
from Virus_Scan.scanners.api.archive_contracts import scan_archive_file, scan_rpa_file
from Virus_Scan.scanners.api.binary_contracts import should_binary_failover
from Virus_Scan.scanners.api.pickle_contracts import pickle_embedded_payload_tags
from Virus_Scan.scanners.api.static_program_analysis_contracts import (
    STATIC_PROGRAM_ANALYSIS_FRONTENDS,
)
from Virus_Scan.utils.stages import (
    choose_effective_stage,
    get_scan_extension,
    normalize_stage,
    resolve_content_evidence_stage,
)
from Virus_Scan.utils.tagging import normalize_tags


PLR2004N12 = 12


def _route_text(value: object, *, default: object="") -> object:
    text, reason = no_hook_text(
        value,
        missing_reason="route_text_missing",
        unsupported_reason="route_text_rejected",
    )
    return default if reason else text


def _route_identity(identity: object) -> object:
    items = no_hook_mapping_items(identity)
    return {} if items is None else dict(items)


def _route_identity_get(identity: object, key: object, default: object=None) -> object:
    return dict.get(_route_identity(identity), key, default)


def _route_sequence(value: object) -> object:
    return tuple(no_hook_sequence_items(value))


def _route_text_sequence(value: object) -> object:
    out = []
    for item in no_hook_sequence_items(value):
        text = _route_text(item)
        if text:
            out.append(text)
    return tuple(out)


def _route_stage_tag(prefix: object, stage: object) -> object:
    return str.__add__(prefix, _route_text(stage, default="unknown"))


def _route_evidence(
    tags: object,
    *,
    path: object,
    source: str,
    strings_blob: object = "",
) -> TagEvidence:
    values = list(_route_text_sequence(tags))
    modality = "static_string" if "string" in source.lower() else "static_structure"
    observations = artifact_observations_for_path_tags(
        values,
        producer_id=source,
        stage_id="scanner_output",
        path=path,
        strings_blob=strings_blob,
        modality=modality,
    )
    return validate_tag_evidence_input_for_path(
        observations, path=path, strings_blob=strings_blob, source=source,
    )


def _merge_route_evidence(
    bundles: object,
    *,
    path: object,
    source: str,
    strings_blob: object = "",
) -> TagEvidence:
    records = []
    if type(bundles) in (tuple, list):
        for bundle in bundles:
            if type(bundle) is TagEvidence:
                records.extend(bundle.records)
    del path, source, strings_blob
    return merge_tag_evidence_inputs(tuple(
        bundle for bundle in bundles if type(bundle) is TagEvidence
    ))


def _merge_route_tag_inputs(
    tags: object,
    evidence: TagEvidence,
    *,
    path: object,
    source: str,
    strings_blob: object = "",
) -> TagEvidence:
    published = frozenset(
        str.__str__(tag) for tag in evidence.tags if type(tag) is str
    )
    missing = [
        str.__str__(tag)
        for tag in _route_sequence(tags)
        if type(tag) is str and str.__str__(tag) and str.__str__(tag) not in published
    ]
    additions = _route_evidence(
        missing, path=path, source=source, strings_blob=strings_blob,
    ) if missing else TagEvidence()
    return merge_tag_evidence_inputs((evidence, additions))


def _missing_file_outcome(
    path: object,
    original_path: object,
    ext_stage: object,
    identity: object,
    scanner_execution_plan: ScannerExecutionPlan,
) -> object:
    log_error(
        "missing scan file: ext="
        + get_scan_extension(original_path)
        + "; path_type="
        + no_hook_type_name(path)
    )
    tags = ["missing_file", _route_stage_tag("router_stage_", ext_stage)]
    evidence = _route_evidence(tags, path=path, source="router_missing_file")
    owned_identity = _route_identity(identity)
    owned_identity["scanner_execution_plan"] = scanner_execution_plan.to_record()
    return RouteScanOutcome(tags, True, owned_identity, evidence)


def _static_analysis_status(parser_status: str, operation_count: int) -> str:
    if parser_status == "complete":
        return "complete_with_observation" if operation_count else "complete_no_observation"
    if parser_status in {"partial", "truncated", "failed", "unavailable"}:
        return parser_status
    raise ValueError("static_analysis_parser_status_invalid")


def _route_static_program_analysis(
    path: object,
    *,
    artifact_read_snapshot: object,
    scanner_execution_plan: ScannerExecutionPlan,
) -> tuple[TagEvidence, ScannerExecutionPlan, dict[str, object], tuple[object, ...]]:
    selected = tuple(
        frontend
        for frontend in STATIC_PROGRAM_ANALYSIS_FRONTENDS
        if scanner_execution_plan.allows(frontend.scanner_id)
    )
    if not selected:
        return (
            TagEvidence(),
            scanner_execution_plan,
            empty_static_analysis_summary(status="not_applicable"),
            (),
        )
    if len(selected) != 1:
        raise RuntimeError("static_analysis_frontend_selection_ambiguous")
    frontend = selected[0]
    scanner_id = frontend.scanner_id
    result = frontend.analyzer(artifact_read_snapshot)
    analysis = result.analysis
    observations = tuple(
        observation
        for operation in analysis.operations
        for observation in project_static_operation_observations(
            analysis,
            operation,
            producer_id=scanner_id,
            stage_id="static_operation_projection",
        )
    )
    evidence = validate_tag_evidence_input_for_path(
        observations, path=path, source=scanner_id,
    ) if observations else TagEvidence()
    status = _static_analysis_status(analysis.parser_status, len(analysis.operations))
    scanner_execution_plan = scanner_execution_plan.with_outcome(
        scanner_id,
        status,
        analysis.unavailable_reason,
    )
    return (
        evidence,
        scanner_execution_plan,
        build_static_analysis_summary(
            analysis,
            scanner_id=scanner_id,
            cache_source=result.cache_source,
        ),
        (analysis,),
    )


def _route_pickle_probe(
    path: object,
    ext: object,
    tags: object,
    suspicious: object,
    *,
    artifact_read_snapshot: object,
    scanner_execution_plan: ScannerExecutionPlan,
) -> tuple[object, TagEvidence, ScannerExecutionPlan]:
    if not scanner_execution_plan.allows("pickle_embedded_payload"):
        return suspicious, TagEvidence(), scanner_execution_plan
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    pickle_tags = pickle_embedded_payload_tags(snapshot.read_prefix(2 * 1024 * 1024), path=path)
    if pickle_tags:
        tags.extend(pickle_tags)
        evidence = _route_evidence(
            pickle_tags, path=path, source="pickle_embedded_payload",
        )
        scanner_execution_plan = scanner_execution_plan.with_outcome(
            "pickle_embedded_payload", scanner_result_status(pickle_tags),
        )
        return suspicious or has_any_tag(
            pickle_tags,
            "pickle_dangerous_global",
            "pickle_callable_reference",
            "pickle_reduce_opcode",
            "process_exec",
        ), evidence, scanner_execution_plan
    scanner_execution_plan = scanner_execution_plan.with_outcome(
        "pickle_embedded_payload", "complete_no_observation",
    )
    return suspicious, TagEvidence(), scanner_execution_plan


def _route_archive_stage(
    path: object,
    ext: object,
    identity: object,
    archive_depth: object,
    tags: object,
    suspicious: object,
    scanner_execution_plan: ScannerExecutionPlan,
) -> tuple[object, TagEvidence, ScannerExecutionPlan]:
    report_scan_stage_progress("archive_route")
    bundles = []
    identity_magic_type = _route_text(_route_identity_get(identity, "magic_type", "")).lower()
    linked_members = []
    if scanner_execution_plan.allows("archive_graph"):
        linked_members = route_archive_members_to_graph(path)
        scanner_execution_plan = scanner_execution_plan.with_outcome(
            "archive_graph", scanner_result_status(("archive_member_graph",) if linked_members else ()),
        )
    if linked_members:
        tags.append("archive_member_graph")
        bundles.append(_route_evidence(
            ["archive_member_graph"], path=path, source="archive_graph",
        ))
    stage_tags = []
    stage_suspicious = False
    source = "archive_scanner"
    if scanner_execution_plan.allows("rpa_archive"):
        stage_tags, stage_suspicious = scan_rpa_file(path)
        scanner_execution_plan = scanner_execution_plan.with_outcome(
            "rpa_archive", scanner_result_status(stage_tags),
        )
        source = "rpa_archive_scanner"
    elif scanner_execution_plan.allows("generic_archive"):
        stage_tags, stage_suspicious = scan_archive_file(path, archive_depth=archive_depth)
        scanner_execution_plan = scanner_execution_plan.with_outcome(
            "generic_archive", scanner_result_status(stage_tags),
        )
        source = "archive_scanner"
    stage_items = _route_sequence(stage_tags)
    tags.extend(stage_items)
    bundles.append(_route_evidence(stage_items, path=path, source=source))
    return suspicious or bool(stage_suspicious), _merge_route_evidence(
        bundles, path=path, source="archive_stage_merge",
    ), scanner_execution_plan


def _finalize_route(
    *,
    path: object,
    ext_stage: object,
    effective_stage: object,
    identity: object,
    tags: object,
    tag_evidence: TagEvidence,
    suspicious: object,
    asset_score: object,
    strings_for_validation: object,
    binary_failover_ran: object,
    artifact_read_snapshot: object,
) -> object:
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    identity_tags = list(_route_text_sequence(_route_identity_get(identity, "tags", ())))
    common_tags = [*identity_tags, _route_stage_tag("router_stage_", effective_stage)]
    tags_before_common = [tag for tag in tags if tag not in common_tags]
    terminal_clean_passive = effective_stage in {"asset", "image"} and _is_terminal_clean_asset_triage(tags, suspicious=suspicious)
    if terminal_clean_passive:
        strings_for_validation = strings_for_validation or ""
    elif not strings_for_validation:
        report_scan_stage_progress("validation_read")
        raw_for_validation = snapshot.read_prefix(1_500_000)
        if type(raw_for_validation) is bytes:
            strings_for_validation = raw_for_validation.decode("latin1", errors="ignore")
        elif type(raw_for_validation) is bytearray:
            strings_for_validation = bytes(raw_for_validation).decode("latin1", errors="ignore")
        else:
            strings_for_validation = _route_text(raw_for_validation)

    initial_inputs = _merge_route_tag_inputs(
        tags, tag_evidence, path=path, source="router", strings_blob=strings_for_validation,
    )
    generation = finalize_tag_evidence_generation(
        initial_inputs, path=path, strings_blob=strings_for_validation, source=("router:merge" if terminal_clean_passive else "router_failover:merge"),
    )
    tags = list(generation.evidence.tags)

    if not terminal_clean_passive:
        normalized_once = normalize_tags(tags)
        if should_binary_failover(ext_stage, effective_stage, identity, tags_before_common, normalized_once):
            report_scan_stage_progress("binary_failover")
            try:
                failover_tags = []
                if failover_tags:
                    tags.extend(failover_tags)
                tags.append("binary_failover_scan")
                binary_failover_ran = True
            except RECOVERABLE_RUNTIME_ERRORS as exc:
                record_detector_error(
                    "binary_failover_scan",
                    exc,
                    context={"file": path, "ext_stage": ext_stage, "effective_stage": effective_stage},
                )
                tags.append("binary_failover_error")
                suspicious = True
        if binary_failover_ran:
            tags.append("scan_failsafe_applied")
        failover_inputs = _merge_route_tag_inputs(
            tags, generation.input_evidence, path=path, source="router_failover",
            strings_blob=strings_for_validation,
        )
        generation = finalize_tag_evidence_generation(
            failover_inputs, path=path, strings_blob=strings_for_validation,
            source="router_failover:merge", previous_generation=generation,
        )
        tags = list(generation.evidence.tags)

    observed_stage = resolve_content_evidence_stage(effective_stage, tags)
    if observed_stage != effective_stage:
        effective_stage = observed_stage
        tags = [tag for tag in tags if not _route_text(tag).startswith("router_stage_")]
        tags.append(_route_stage_tag("router_stage_", effective_stage))
        tags.append(_route_stage_tag("observed_stage_", effective_stage))
        observed_inputs = _merge_route_tag_inputs(
            tags, generation.input_evidence, path=path, source="router_observed_stage",
            strings_blob=strings_for_validation,
        )
        generation = finalize_tag_evidence_generation(
            observed_inputs, path=path, strings_blob=strings_for_validation,
            source="router_observed_stage:merge", previous_generation=generation,
        )
        tags = list(generation.evidence.tags)

    scoreable_evidence = scoreable_tag_evidence(
        generation.evidence,
        allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    chain_evidence = evaluate_chain_evidence(tags=scoreable_evidence)
    stage_score, stage_hits = staged_enrichment_score(
        scoreable_evidence, chain_evidence, effective_stage, asset_score,
    )
    if stage_score >= PLR2004N12:
        suspicious = True
        tags.extend(["staged_detection", *["stage_hit:" + hit for hit in stage_hits[:8]]])
        scoring_inputs = _merge_route_tag_inputs(
            tags, generation.input_evidence, path=path, source="router_stage_scoring",
            strings_blob=strings_for_validation,
        )
        generation = finalize_tag_evidence_generation(
            scoring_inputs, path=path, strings_blob=strings_for_validation,
            source="router_stage_scoring:merge", previous_generation=generation,
        )
        tags = list(generation.evidence.tags)
    return tags, generation, suspicious, effective_stage, strings_for_validation, binary_failover_ran


def _remember_route_evidence(path: object, effective_stage: object, identity: object, suspicious: object, asset_score: object, binary_failover_ran: object, tags: object, strings_for_validation: object) -> None:
    try:
        _remember_scan_evidence(
            path,
            strings_blob=strings_for_validation,
            effective_stage=effective_stage,
            identity=identity,
            suspicious=suspicious,
            asset_score=asset_score,
            binary_failover_ran=binary_failover_ran,
            tags=list(_route_sequence(tags)),
        )
    except RECOVERABLE_RUNTIME_ERRORS as suppressed_exc:
        try:
            record_suppressed_failure("suppressed_exception", suppressed_exc, domain="runtime")
        except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
            _ = reporting_exc


def scan_file_by_type(
    path: object,
    archive_depth: object = 0,
    *,
    scan_session_snapshot: object,
    artifact_read_snapshot: object,
) -> object:
    """Canonical staged scanner router with producer-preserving evidence."""
    if type(scan_session_snapshot) is not ScanSessionSnapshot:
        raise TypeError("router_scan_session_snapshot_required")
    session = scan_session_snapshot
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    original_path = path
    ext = get_scan_extension(path)
    ext_stage = normalize_stage(ext)
    identity = {"ext": ext, "ext_stage": ext_stage, "magic_stage": "unknown", "tags": []}
    effective_stage = ext_stage
    tags = []
    evidence_bundles = []
    tag_evidence = TagEvidence()
    suspicious = False
    asset_score = 0.0
    binary_failover_ran = False
    strings_for_validation = ""
    scanner_execution_plan = build_scanner_execution_plan(
        scan_session_snapshot=session,
        artifact_read_snapshot=snapshot,
        extension=ext,
        effective_stage=effective_stage,
        identity=identity,
        archive_depth=archive_depth,
    )
    try:
        report_scan_stage_progress("router_start")
        if not snapshot.complete or not os.path.exists(path) or not os.path.isfile(path):
            return _missing_file_outcome(path, original_path, ext_stage, identity, scanner_execution_plan)
        identity = _route_identity(sniff_file_identity_from_snapshot(path, snapshot))
        report_scan_stage_progress("router_identity", bytes_delta=8192)
        effective_stage = choose_effective_stage(ext_stage, identity)
        scanner_execution_plan = build_scanner_execution_plan(
            scan_session_snapshot=session,
            artifact_read_snapshot=snapshot,
            extension=ext,
            effective_stage=effective_stage,
            identity=identity,
            archive_depth=archive_depth,
        )
        identity_tags = list(_route_text_sequence(_route_identity_get(identity, "tags", ())))
        tags.extend(identity_tags)
        if identity_tags:
            evidence_bundles.append(_route_evidence(
                identity_tags, path=path, source="file_identity",
            ))
        router_stage_tag = _route_stage_tag("router_stage_", effective_stage)
        tags.append(router_stage_tag)
        evidence_bundles.append(_route_evidence(
            [router_stage_tag], path=path, source="router_stage",
        ))
        static_evidence, scanner_execution_plan, static_summary, static_program_analyses = _route_static_program_analysis(
            path,
            artifact_read_snapshot=snapshot,
            scanner_execution_plan=scanner_execution_plan,
        )
        identity["static_program_analysis"] = static_summary
        if static_evidence.records:
            tags.extend(static_evidence.tags)
            evidence_bundles.append(static_evidence)
        suspicious, pickle_evidence, scanner_execution_plan = _route_pickle_probe(
            path,
            ext,
            tags,
            suspicious,
            artifact_read_snapshot=snapshot,
            scanner_execution_plan=scanner_execution_plan,
        )
        evidence_bundles.append(pickle_evidence)
        identity_tag_set = set(identity_tags)
        if "extension_mismatch" in identity_tag_set or "extension_magic_type_mismatch" in identity_tag_set:
            suspicious = True
        if ext == ".cs" and effective_stage in {"cs", "asset", "runtime"}:
            if scanner_execution_plan.allows("csharp_graph"):
                raw_cs_tags = list(_route_sequence(route_cs_graph_tags(path)))
                scanner_execution_plan = scanner_execution_plan.with_outcome(
                    "csharp_graph", scanner_result_status(raw_cs_tags),
                )
                cs_tags = ["source_cs", *raw_cs_tags]
                tags.extend(cs_tags)
                evidence_bundles.append(_route_evidence(
                    cs_tags, path=path, source="csharp_graph_scanner",
                ))
        elif effective_stage == "archive":
            suspicious, archive_evidence, scanner_execution_plan = _route_archive_stage(
                path, ext, identity, archive_depth, tags, suspicious, scanner_execution_plan,
            )
            evidence_bundles.append(archive_evidence)
        elif effective_stage == "asset":
            stage_evidence, stage_suspicious, asset_score, _, strings_for_validation, scanner_execution_plan = route_asset_stage(
                path,
                ext,
                identity,
                artifact_read_snapshot=snapshot,
                scanner_execution_plan=scanner_execution_plan,
            )
            tags.extend(stage_evidence.tags)
            evidence_bundles.append(stage_evidence)
            suspicious = suspicious or stage_suspicious
        elif effective_stage == "binary":
            stage_evidence, stage_suspicious, scanner_execution_plan = route_binary_stage(
                path,
                identity,
                artifact_read_snapshot=snapshot,
                scanner_execution_plan=scanner_execution_plan,
            )
            tags.extend(stage_evidence.tags)
            evidence_bundles.append(stage_evidence)
            suspicious = suspicious or stage_suspicious
        elif effective_stage == "image":
            stage_evidence, stage_suspicious, strings_for_validation, scanner_execution_plan = route_image_stage(
                path,
                artifact_read_snapshot=snapshot,
                scanner_execution_plan=scanner_execution_plan,
            )
            tags.extend(stage_evidence.tags)
            evidence_bundles.append(stage_evidence)
            suspicious = suspicious or stage_suspicious
        elif effective_stage == "runtime":
            stage_evidence, stage_suspicious, strings_for_validation, scanner_execution_plan = route_runtime_stage(
                path,
                ext,
                artifact_read_snapshot=snapshot,
                scanner_execution_plan=scanner_execution_plan,
            )
            tags.extend(stage_evidence.tags)
            evidence_bundles.append(stage_evidence)
            suspicious = suspicious or stage_suspicious
        else:
            stage_evidence, scanner_execution_plan = route_other_stage(
                path,
                artifact_read_snapshot=snapshot,
                scanner_execution_plan=scanner_execution_plan,
            )
            tags.extend(stage_evidence.tags)
            evidence_bundles.append(stage_evidence)

        tag_evidence = _merge_route_evidence(
            evidence_bundles,
            path=path,
            source="router_collector_merge",
            strings_blob=strings_for_validation,
        )
        tags, tag_generation, suspicious, effective_stage, strings_for_validation, binary_failover_ran = _finalize_route(
            path=path,
            ext_stage=ext_stage,
            effective_stage=effective_stage,
            identity=identity,
            tags=tags,
            tag_evidence=tag_evidence,
            suspicious=suspicious,
            asset_score=asset_score,
            strings_for_validation=strings_for_validation,
            binary_failover_ran=binary_failover_ran,
            artifact_read_snapshot=snapshot,
        )
        pending_scanners = scanner_execution_plan.pending_scanner_ids()
        if pending_scanners:
            suspicious = True
            tags.extend(["scanner_execution_plan_incomplete", *["scanner_pending:" + item for item in pending_scanners]])
            scanner_execution_plan = scanner_execution_plan.with_pending_outcomes(
                "failed", "scanner_selected_but_not_executed",
            )
            pending_inputs = _merge_route_tag_inputs(
                tags, tag_generation.input_evidence, path=path,
                source="scanner_execution_plan", strings_blob=strings_for_validation,
            )
            tag_generation = finalize_tag_evidence_generation(
                pending_inputs, path=path, strings_blob=strings_for_validation,
                source="scanner_execution_plan:merge", previous_generation=tag_generation,
            )
            tags = list(tag_generation.evidence.tags)
        emit_stage_event(path, effective_stage, tags)
        _remember_route_evidence(path, effective_stage, identity, suspicious, asset_score, binary_failover_ran, tags, strings_for_validation)
        outcome_identity = _route_identity(identity)
        outcome_identity["scanner_execution_plan"] = scanner_execution_plan.to_record()
        return RouteScanOutcome(
            normalize_tags(tags),
            suspicious,
            outcome_identity,
            tag_generation.evidence,
            static_program_analyses,
        )
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_detector_error(
            "scan_file_by_type",
            exc,
            context={"file": path, "stage": effective_stage, "ext_stage": ext_stage, "identity": identity},
        )
        scanner_execution_plan = scanner_execution_plan.with_pending_outcomes(
            "failed", "scan_router_exception_before_completion",
        )
        error_tags = normalize_tags(tags + ["scan_router_error"])
        error_inputs = _merge_route_tag_inputs(
            error_tags, tag_evidence, path=path, source="scan_router_error",
            strings_blob=strings_for_validation,
        )
        error_generation = finalize_tag_evidence_generation(
            error_inputs, path=path, strings_blob=strings_for_validation,
            source="scan_router_error:merge",
        )
        outcome_identity = _route_identity(identity)
        outcome_identity["scanner_execution_plan"] = scanner_execution_plan.to_record()
        return RouteScanOutcome(error_tags, True, outcome_identity, error_generation.evidence)


__all__ = ("scan_file_by_type",)
