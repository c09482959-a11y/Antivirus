"""Bounded raw-stage chunk collector dispatch helpers."""
from __future__ import annotations

RAW_CHUNK_COLLECTORS = frozenset({
    "pe_api_chunk", "pure_pe_chunk", "dotnet_chunk", "unity_dotnet_chunk",
    "il2cpp_chunk", "bytecode_chunk", "renpy_chunk", "rpgm_js_ast_chunk",
})


def dispatch_raw_chunk_collector(
    *,
    path: object,
    collector: str,
    start: int,
    size: int,
    out: dict[str, object],
    deps: object,
    report: object | None = None,
) -> dict[str, object]:
    """Dispatch one raw chunk collector and store tags/blob output."""
    suppression_reporter = deps.record_suppressed if report is None else report
    if collector == "pe_api_chunk":
        tmp = deps.pe_api_chunk(path, start=start, size=size, read_range_text_func=deps.read_range_text)
    elif collector == "pure_pe_chunk":
        request = deps.contextual_chunk_request_factory(
            path, start, size, deps.read_range_text, deps.should_context_scan,
            deps.contextual_tag_scan, deps.context_failure,
        )
        tmp = deps.pure_pe_chunk_request_owner(request)
    elif collector == "dotnet_chunk":
        request = deps.contextual_chunk_request_factory(
            path, start, size, deps.read_range_text, deps.should_context_scan,
            deps.contextual_tag_scan, deps.context_failure,
        )
        tmp = deps.dotnet_chunk_request_owner(request)
    elif collector == "unity_dotnet_chunk":
        tmp = deps.unity_dotnet_chunk(
            path,
            start=start,
            size=size,
            read_range_text_func=deps.read_range_text,
            extract_il_patterns=deps.extract_il_patterns,
            analyze_il_pipeline=deps.analyze_il_pipeline,
            should_context_scan_func=deps.should_context_scan,
            contextual_scan=deps.contextual_tag_scan,
            context_failure=deps.context_failure,
            report_issue=deps.record_issue,
        )
    elif collector == "il2cpp_chunk":
        tmp = deps.il2cpp_chunk(
            path,
            start=start,
            size=size,
            read_range_text_func=deps.read_range_text,
            runtime_value=deps.runtime_value,
            detect_unity_runtime_behavior=deps.detect_unity_runtime_behavior,
            byte_entropy=deps.byte_entropy,
            report=suppression_reporter,
            recoverable_exceptions=deps.recoverable_exceptions,
        )
    elif collector == "bytecode_chunk":
        request = deps.bytecode_chunk_request_factory(
            path, start, size, deps.read_range_text, deps.get_scan_extension,
            deps.detect_pickle_exec, deps.should_context_scan, deps.contextual_tag_scan,
            deps.context_failure, suppression_reporter, deps.recoverable_exceptions,
        )
        tmp = deps.bytecode_chunk_request_owner(request)
    elif collector == "renpy_chunk":
        tmp = deps.renpy_chunk(path, start=start, size=size)
    elif collector == "rpgm_js_ast_chunk":
        tmp = deps.rpgm_js_ast_chunk(path, start=start, size=size)
    else:
        tmp = {}
    out["tags"] = tmp.get("tags", [])
    out["strings_blob"] = tmp.get("strings_blob", "")
    return out


__all__ = ("RAW_CHUNK_COLLECTORS", "dispatch_raw_chunk_collector")
