"""Terminal-result ownership for single-file scheduler execution."""
from __future__ import annotations

from Virus_Scan.scheduler.execution.file_result_boundary import (
    execution_bool,
    execution_float,
    execution_record_mapping,
    execution_path_text,
    execution_result_degraded,
)
from Virus_Scan.scheduler.execution.scheduler_file_message_support import scheduler_slow_file_message
from Virus_Scan.scheduler.execution.scheduler_yara_result import (
    obtain_scheduler_yara_result,
    publish_scheduler_yara_result,
)


def maybe_return_terminal_result(
    *,
    request: object,
    deps: object,
    path: object,
    started_file: float,
    tags: object,
    suspicious: bool,
    curr_stage: str,
    router_identity: object,
    active_timeout_budget: object,
    cache_sha256: str,
) -> tuple[object, dict[str, object]] | None:
    """Return terminal asset result when routing says no deeper execution is needed."""
    if not deps.terminal_asset_triage(tags, suspicious=suspicious):
        return None
    result = execution_record_mapping(
        deps.make_terminal_asset_result(
            path,
            tags,
            prev_stage=request.previous_stage,
            curr_stage=curr_stage,
            cache_sha256=cache_sha256,
        ),
        field_name="terminal_result",
    )
    result = execution_record_mapping(
        deps.attach_routing_evidence_to_record(
            result,
            path,
            container_root=request.root,
            tags=(
                tags
                if dict.get(result, "tags") is None
                else dict.get(result, "tags")
            ),
            trusted_benign=execution_bool(
                dict.get(result, "trusted_benign"),
                field_name="trusted_benign",
            ),
            degraded=execution_result_degraded(result),
            evidence_context=request.routing_evidence_context,
            router_identity=router_identity,
        ),
        field_name="terminal_routing_result",
    )
    yara_result = obtain_scheduler_yara_result(
        path=path,
        yara_enabled=request.yara_enabled,
        compiled_rules=request.compiled_rules,
        yara_scan_with_optional_zip=deps.yara_scan_with_optional_zip,
    )
    publish_scheduler_yara_result(result, yara_result)
    elapsed_file = deps.time() - started_file
    result["scan_duration_seconds"] = round(elapsed_file, 6)
    result["timeout_evidence"] = active_timeout_budget.as_evidence()
    slow_threshold = execution_float(
        request.slow_file_warn_sec,
        field_name="slow_file_warn_sec",
        minimum=0.0,
    )
    if slow_threshold > 0.0 and elapsed_file > slow_threshold:
        path_text = execution_path_text(path, field_name="scan_path")
        deps.warn_slow_file(
            scheduler_slow_file_message(
                elapsed_file=elapsed_file,
                path_text=path_text,
                basename=deps.basename,
            )
        )
        result["slow_file_seconds"] = round(elapsed_file, 3)
    return (path, result)
