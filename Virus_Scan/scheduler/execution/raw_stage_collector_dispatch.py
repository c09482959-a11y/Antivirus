"""Bounded raw-stage collector dispatch for scheduler execution.

The raw-stage executor owns execution flow, cache boundaries, and failure
conversion.  This module owns collector-specific dispatch so the executor does
not accumulate scanner-family branching, chunk handling, and YARA dispatch in a
single mixed-purpose function.
"""
from __future__ import annotations

from Virus_Scan.scheduler.execution.raw_stage_chunk_collectors import (
    RAW_CHUNK_COLLECTORS,
    dispatch_raw_chunk_collector,
)
from Virus_Scan.scheduler.execution.raw_stage_collector_dispatch_groups import (
    RAW_HEADER_COLLECTORS,
    RAW_TEXT_COLLECTORS,
    dispatch_raw_header_collector,
    dispatch_raw_text_collector,
)
from Virus_Scan.scheduler.execution.raw_stage_collector_dispatch_support import unknown_collector_error
from Virus_Scan.contracts.yara_hits import (
    YaraScanResult,
    unavailable_yara_scan_result,
    yara_scan_result_record,
)
from Virus_Scan.yara.execution_policy import selected_yara_snapshot, yara_light_selected



def dispatch_raw_stage_collector(
    *,
    job: dict[str, object],
    path: object,
    collector: str,
    start: int,
    size: int,
    out: dict[str, object],
    deps: object,
) -> dict[str, object]:
    """Execute one raw collector and return the explicit collector result."""
    if collector == "identity":
        out["tags"] = deps.micro_stage_collect("file_identity", path)
    elif collector in RAW_TEXT_COLLECTORS:
        out = dispatch_raw_text_collector(
            path=path,
            collector=collector,
            start=start,
            size=size,
            out=out,
            deps=deps,
            report=deps.record_suppressed,
        )
    elif collector in RAW_HEADER_COLLECTORS:
        out = dispatch_raw_header_collector(path=path, collector=collector, out=out, deps=deps)
    elif collector in RAW_CHUNK_COLLECTORS:
        out = dispatch_raw_chunk_collector(
            path=path,
            collector=collector,
            start=start,
            size=size,
            out=out,
            deps=deps,
        )
    elif collector == "rpgm":
        out["tags"] = deps.scan_rpgm_file(path) or []
    elif collector == "yara":
        try:
            yara_evidence = deps.yara_scan_with_optional_zip(
                path,
                compiled_rules=selected_yara_snapshot(deps.yara_rules_state()),
            )
            if type(yara_evidence) is not YaraScanResult:
                raise TypeError("raw_stage_yara_scan_result_invalid")
            out["yara_evidence"] = yara_scan_result_record(yara_evidence)
            out["yara_hits"] = deps.normalize_yara_hits(yara_evidence)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            out = deps.raw_stage_failure_result(out, collector, exc, stage="raw_stage_yara")
            failed_result = unavailable_yara_scan_result(
                "raw_stage_yara_failure:" + type(exc).__name__,
                status="failed",
            )
            out["yara_evidence"] = yara_scan_result_record(failed_result)
            out["yara_hits"] = []
    else:
        out = deps.raw_stage_failure_result(
            out,
            collector,
            unknown_collector_error(collector),
            stage="raw_stage_unknown_collector",
        )
    return out
