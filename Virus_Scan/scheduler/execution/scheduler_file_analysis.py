"""Deep/YARA analysis ownership for single-file scheduler execution."""
from __future__ import annotations

from Virus_Scan.scheduler.execution.scheduler_file_analysis_steps import (
    build_scheduler_analysis_guard,
    compute_scheduler_analysis_budget,
)
from Virus_Scan.scheduler.execution.scheduler_file_analysis_record_steps import (
    build_scheduler_analysis_record,
    finalize_scheduler_analysis_record,
)


def execute_scheduler_file_analysis(
    *,
    request: object,
    deps: object,
    path: object,
    started_file: float,
    tags: object,
    suspicious: bool,
    curr_stage: str,
    router_identity: object,
    route_tag_evidence: object,
    route_static_program_analyses: object = (),
    prefilter_info: dict[str, object],
    global_raw_info: dict[str, object] | None,
) -> tuple[object, dict[str, object]]:
    """Execute the non-terminal scheduler analysis path."""
    global_raw_snapshot: dict[object, object] = (
        dict(global_raw_info) if type(global_raw_info) is dict else {}
    )
    global_raw_input = (
        global_raw_snapshot if type(global_raw_info) is dict else global_raw_info
    )
    _deep_scan_escalated, active_timeout_budget = compute_scheduler_analysis_budget(
        request=request,
        deps=deps,
        path=path,
        tags=tags,
        suspicious=suspicious,
        prefilter_info=prefilter_info,
        curr_stage=curr_stage,
    )
    analysis_guard = build_scheduler_analysis_guard(
        request=request,
        deps=deps,
        active_timeout_budget=active_timeout_budget,
    )
    with analysis_guard:
        yara_hits, result = build_scheduler_analysis_record(
            request=request,
            deps=deps,
            path=path,
            tags=tags,
            curr_stage=curr_stage,
            router_identity=router_identity,
            route_tag_evidence=route_tag_evidence,
            route_static_program_analyses=route_static_program_analyses,
            prefilter_info=prefilter_info,
            global_raw_info=global_raw_input,
        )
        return (
            path,
            finalize_scheduler_analysis_record(
                request=request,
                deps=deps,
                path=path,
                started_file=started_file,
                result=result,
                curr_stage=curr_stage,
                suspicious=suspicious,
                yara_hits=yara_hits,
                active_timeout_budget=active_timeout_budget,
            ),
        )


__all__ = ("execute_scheduler_file_analysis",)
