"""Record-building helper steps for scheduler file analysis."""
from __future__ import annotations

from Virus_Scan.scheduler.execution.file_result_boundary import (
    execution_bool,
    execution_mapping,
    execution_record_mapping,
    execution_result_degraded,
    execution_sequence,
    execution_text,
)
from Virus_Scan.scheduler.execution.scheduler_file_analysis_steps import record_scheduler_slow_file
from Virus_Scan.scheduler.execution.scheduler_yara_result import (
    obtain_scheduler_yara_result,
    publish_scheduler_yara_result,
)



def materialize_global_raw_snapshot(global_raw_info: dict[str, object] | None) -> dict[object, object]:
    """Materialize global raw info without invoking caller-owned hooks."""
    if global_raw_info is None:
        return {}
    return execution_mapping(global_raw_info, field_name="global_raw_info")


def build_scheduler_analysis_record(
    *,
    request: object,
    deps: object,
    path: object,
    tags: object,
    curr_stage: str,
    router_identity: object,
    route_tag_evidence: object,
    route_static_program_analyses: object,
    prefilter_info: dict[str, object],
    global_raw_info: dict[str, object] | None,
) -> tuple[object, dict[str, object]]:
    """Run observe-only analysis and attach routing evidence."""
    global_raw_snapshot = materialize_global_raw_snapshot(global_raw_info)
    raw_yara_result = dict.get(global_raw_snapshot, "yara_evidence")
    yara_evidence = obtain_scheduler_yara_result(
        path=path,
        yara_enabled=request.yara_enabled,
        compiled_rules=request.compiled_rules,
        yara_scan_with_optional_zip=deps.yara_scan_with_optional_zip,
        existing_result=raw_yara_result,
    )
    strings_blob = execution_text(
        dict.get(global_raw_snapshot, "strings_blob"),
        field_name="strings_blob",
        default="",
    )[:65536]
    result = execution_record_mapping(
        deps.analyze_file_full_observe_only(
            path,
            tags=route_tag_evidence,
            static_program_analyses=route_static_program_analyses,
            yara_hits=yara_evidence,
            prev_stage=request.previous_stage,
            curr_stage=curr_stage,
            strings_blob=strings_blob,
            strings_already_enriched=len(global_raw_snapshot) > 0,
            routing_evidence_context=request.routing_evidence_context,
            router_identity=router_identity,
            scan_session_snapshot=request.scan_session_snapshot,
            artifact_read_snapshot=request.artifact_read_snapshot,
        ),
        field_name="analysis_result",
    )
    return yara_evidence, attach_scheduler_routing_evidence(
        request=request,
        deps=deps,
        path=path,
        tags=tags,
        result=result,
        router_identity=router_identity,
    )


def attach_scheduler_routing_evidence(
    *,
    request: object,
    deps: object,
    path: object,
    tags: object,
    result: dict[str, object],
    router_identity: object,
) -> dict[str, object]:
    """Attach routing evidence to the scheduler analysis record."""
    return execution_record_mapping(
        deps.attach_routing_evidence_to_record(
            result,
            path,
            container_root=request.root,
            tags=tags if dict.get(result, "tags") is None else dict.get(result, "tags"),
            trusted_benign=execution_bool(dict.get(result, "trusted_benign"), field_name="trusted_benign"),
            degraded=execution_result_degraded(result),
            evidence_context=request.routing_evidence_context,
            router_identity=router_identity,
        ),
        field_name="routing_result",
    )


def finalize_scheduler_analysis_record(
    *,
    request: object,
    deps: object,
    path: object,
    started_file: float,
    result: dict[str, object],
    curr_stage: str,
    suspicious: bool,
    yara_hits: object,
    active_timeout_budget: object,
) -> dict[str, object]:
    """Append public scheduler analysis metadata to the result record."""
    result["effective_stage"] = curr_stage
    result["suspicious_type_router"] = suspicious
    publish_scheduler_yara_result(result, yara_hits)
    result["timeout_evidence"] = active_timeout_budget.as_evidence()
    detector_errors = [
        err
        for err in deps.get_detector_errors(clear=False)
        if err.get("context", {}).get("file") in (None, path)
    ]
    if detector_errors:
        result["detector_errors"] = detector_errors[-20:]
    elapsed_file = deps.time() - started_file
    result["scan_duration_seconds"] = round(elapsed_file, 6)
    record_scheduler_slow_file(
        request=request,
        deps=deps,
        path=path,
        result=result,
        elapsed_file=elapsed_file,
    )
    return result


__all__ = (
    "build_scheduler_analysis_record",
    "finalize_scheduler_analysis_record",
)
