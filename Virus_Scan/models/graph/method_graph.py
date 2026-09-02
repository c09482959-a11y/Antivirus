from __future__ import annotations

import re

from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.graph_state import add_graph_edge_owned, update_graph_node_owned
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.models.graph.common_text_boundaries import graph_exception_message, graph_reasoned_text
from Virus_Scan.models.graph.common import (
    safe_graph_sequence,
    normalize_graph_tags_with_reason,
    record_graph_input_degraded,
    graph_first_reason,
)
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items


def _method_graph_text(value: object, reason: object) -> object:
    text, text_reason = graph_reasoned_text(value, reason)
    return text, text_reason


def _method_graph_sequence(value: object, reason: object) -> object:
    values, sequence_reason = safe_graph_sequence(value, reason)
    return values, sequence_reason


def _method_graph_source_lines(value: object, reason: object) -> object:
    text, text_reason = _method_graph_text(value, reason)
    if text_reason:
        return (), text_reason
    return tuple(str.splitlines(text)), ''


def _method_graph_node_id(file_text: object, method_text: object) -> object:
    return str.__add__(str.__add__(file_text, '::'), method_text)


def add_method_node(src: object, tags: object, calls: object) -> None:
    src_text, src_reason = _method_graph_text(src, 'graph_method_src_unavailable')
    try:
        normalized_tags, tags_reason = normalize_graph_tags_with_reason(tags, 'graph_method_tags_unavailable')
        call_values, calls_reason = _method_graph_sequence(calls, 'graph_method_calls_unavailable')
        input_reason = graph_first_reason(src_reason, tags_reason, calls_reason)
        record_graph_input_degraded('graph_method_node_input_degraded', input_reason, node=src_text)
        update_graph_node_owned(src_text, tags=normalized_tags)
        for call_text in call_values:
            add_graph_edge_owned(src_text, call_text, edge_type='method_call', weight=1.0)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_suppressed_failure(
            'add_method_node_failed',
            exc,
            domain='model',
            tags=['graph_input_degraded'],
            context={'node': src_text},
        )
        log_error(graph_exception_message('add_method_node failed: ', exc))


def extract_methods(cs_text: object) -> object:
    """Graph-owned C# method extractor used by scan_cs()."""
    methods = {}
    current = None
    brace_depth = 0
    buf = []
    method_header = re.compile(r'(?:public|private|protected|internal)?\s*(?:static\s+)?[\w<>,\[\]]+\s+\w+\s*\([^)]*\)')
    source_lines, source_reason = _method_graph_source_lines(cs_text, 'graph_method_source_unavailable')
    if source_reason:
        record_graph_input_degraded('graph_method_source_degraded', source_reason)
        return methods
    for line in source_lines:
        stripped = line.strip()
        if stripped.startswith('['):
            continue
        if current is None and method_header.search(stripped) and '{' in stripped:
            current = stripped
            brace_depth = stripped.count('{') - stripped.count('}')
            buf = [stripped]
            continue
        if current is not None:
            brace_depth += stripped.count('{') - stripped.count('}')
            buf.append(stripped)
            if brace_depth <= 0:
                methods[current] = '\n'.join(buf)
                current = None
                buf = []
    return methods


def extract_calls(method_body: object) -> object:
    """Graph-owned C#/IL-style call extractor used by method graph construction."""
    calls = []
    ignore = {'if', 'for', 'while', 'switch', 'catch', 'using', 'return', 'foreach', 'lock'}
    body_lines, body_reason = _method_graph_source_lines(method_body, 'graph_method_body_unavailable')
    if body_reason:
        record_graph_input_degraded('graph_method_body_degraded', body_reason)
        return ordered_unique_tags(calls)
    for line in body_lines:
        for match in re.findall(r'\b([A-Za-z_][A-Za-z0-9_\.]*)\s*\(', line):
            name = match.split('.')[-1]
            if name in ignore:
                continue
            low = match.lower()
            if 'process.start' in low or low.endswith('runtime.exec'):
                calls.append('process_exec')
            elif 'assembly.load' in low:
                calls.append('assembly_load')
            elif 'getmethod' in low or 'invoke' in low:
                calls.append('reflection')
            elif 'addcomponent' in low:
                calls.append('unity_dynamic_component')
            elif 'startcoroutine' in low:
                calls.append('unity_async_flow')
            else:
                calls.append(match)
    return ordered_unique_tags(calls)


def _method_graph_items(methods: object) -> object:
    if methods is None:
        return (), ''
    items = no_hook_mapping_items(methods)
    if items is None:
        return (), 'graph_method_mapping_unavailable'
    normalized = []
    unavailable = ''
    for item in items:
        try:
            mname, body = item
        except RECOVERABLE_RUNTIME_ERRORS:
            if unavailable == '':
                unavailable = 'graph_method_entry_unavailable'
            continue
        name_text, name_reason = _method_graph_text(mname, 'graph_method_name_unavailable')
        if name_reason:
            if unavailable == '':
                unavailable = graph_first_reason(name_reason)
            continue
        normalized.append((name_text, body))
    return tuple(normalized), unavailable


def build_method_graph(file: object, methods: object=None) -> None:
    """Build method-call graph edges from explicit method text owned by caller."""
    method_items, methods_reason = _method_graph_items(methods)
    file_text, file_reason = _method_graph_text(file, 'graph_method_file_unavailable')
    graph_reason = graph_first_reason(file_reason, methods_reason)
    record_graph_input_degraded('graph_method_graph_input_degraded', graph_reason, node=file_text)
    for mname, body in method_items:
        fid = _method_graph_node_id(file_text, mname)
        calls = extract_calls(body)
        add_method_node(fid, (), calls)


__all__ = ('add_method_node', 'build_method_graph', 'extract_calls', 'extract_methods')
