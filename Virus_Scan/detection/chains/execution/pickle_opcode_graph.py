"""Canonical detection classification owner for pickle opcode graph tags."""
from __future__ import annotations

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.contracts.path_identity import get_scan_extension, path_identity
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_text
from Virus_Scan.detection.contracts.pickle_graph_analysis import (
    analyze_pickle_opcode_graph,
    unify_pickle_detection_tags,
)
from Virus_Scan.detection.contracts.pickle_opcode import RENPY_PICKLE_EXTENSIONS
from Virus_Scan.detection.chains.execution.text_boundaries import (
    pickle_global_trigger_text,
    pickle_opcode_window_part,
    pickle_reduce_trigger_text,
)
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage


def _analysis_tuple_field(analysis: object, key: str) -> tuple[object, ...]:
    """Read analysis-owned tuple/list fields without mapping/truthiness hooks."""
    if type(analysis) is not dict or type(key) is not str:
        return ()
    value = dict.get(analysis, key)
    if type(value) is tuple:
        return value
    if type(value) is list:
        return tuple(value)
    return ()


def _analysis_bool_field(analysis: object, key: str) -> bool:
    if type(analysis) is not dict or type(key) is not str:
        return False
    return dict.get(analysis, key) is True


def _analysis_text_field(record: object, key: str, *, default: str='') -> str:
    if type(record) is not dict or type(key) is not str:
        return default
    text, reason = no_hook_text(dict.get(record, key), missing_reason="missing_pickle_graph_text", unsupported_reason="unsafe_pickle_graph_text_rejected")
    return text.strip() if reason == "" else default


def _analysis_int_field(record: object, key: str) -> int:
    if type(record) is not dict or type(key) is not str:
        return 0
    value, reason = no_hook_exact_nonnegative_int(dict.get(record, key), default=0, allow_exact_text=False, reason="unsafe_pickle_graph_integer_rejected")
    return value if reason == "" else 0


def _pickle_graph_parse_failure_tags(analysis: object, path: object) -> tuple[str, ...]:
    if _analysis_int_field(analysis, 'errors') <= 0:
        return ()
    return failure_tags_for_stage('pickle_opcode_graph_parse', 'pickle_opcode_parse_failure', context=path)


def _path_context_text(path: object) -> str:
    try:
        return path_identity(path).raw.lower() if path is not None else ""
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        return "pickle_path_context_unavailable"


def _append_trigger_context_failure_tags(tags: object, analysis: object, path: object) -> None:
    """Inspect already-built opcode trigger windows without caller-owned hooks."""
    try:
        raw_triggers = []
        for rc in _analysis_tuple_field(analysis, 'reduce_chains')[:8]:
            callable_name = _analysis_text_field(rc, 'callable')
            opcode_name = (_analysis_text_field(rc, 'opcode', default='REDUCE') or 'REDUCE').upper()
            stream_off = _analysis_int_field(rc, 'stream_offset')
            op_pos = _analysis_int_field(rc, 'op_position')
            if callable_name:
                raw_triggers.append(pickle_reduce_trigger_text(callable_name, opcode_name, stream_off, op_pos))
        if not raw_triggers:
            for g in _analysis_tuple_field(analysis, 'dangerous_globals')[:8]:
                text, reason = no_hook_text(g, missing_reason='missing_pickle_global_text', unsupported_reason='unsafe_pickle_global_text_rejected')
                global_name = text.strip() if reason == '' else ''
                if global_name:
                    raw_triggers.append(pickle_global_trigger_text(global_name))
        try:
            for tw in _analysis_tuple_field(analysis, 'trigger_windows')[:4]:
                parts = []
                for oprec in _analysis_tuple_field(tw, 'ops')[-8:]:
                    opname = _analysis_text_field(oprec, 'opcode')
                    argtxt = _analysis_text_field(oprec, 'arg')
                    posn = _analysis_int_field(oprec, 'op_position')
                    if argtxt:
                        parts.append(pickle_opcode_window_part(posn, opname, argtxt))
                    elif opname:
                        parts.append(pickle_opcode_window_part(posn, opname))
                if parts:
                    _ = ' | '.join(parts)
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
            tags.extend(failure_tags_for_stage('pickle_trigger_window_extraction', error, context=path))
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        tags.extend(failure_tags_for_stage('pickle_exec_trigger_context', error, context=path))


def pickle_opcode_graph_tags(data: object | None=None, path: object | None=None) -> tuple[str, ...]:
    """Return detection semantic tags from opcode-level pickle graph facts.

    Pickle fragment payload extraction is scanner-owned. This detection function
    interprets opcode graph facts and does not import scanner fragment decoders.
    """
    tags = []
    try:
        input_data = data if type(data) in (bytes, bytearray, memoryview) or data is None else b''
        analysis = analyze_pickle_opcode_graph(input_data if input_data is not None else b'')
        if not _analysis_bool_field(analysis, 'valid_pickle'):
            return unify_pickle_detection_tags(_pickle_graph_parse_failure_tags(analysis, path), path=path)
        tags.extend(['pickle_opcode_inspected', 'pickle_opcode_graph_analyzed'])
        tags.extend(_pickle_graph_parse_failure_tags(analysis, path))
        if _analysis_tuple_field(analysis, 'globals'):
            tags.append('pickle_global_reference')
        if _analysis_bool_field(analysis, 'has_stack_global'):
            tags.append('pickle_stack_global')
        if _analysis_bool_field(analysis, 'has_reduce'):
            tags.append('pickle_reduce_opcode')
        if _analysis_tuple_field(analysis, 'dangerous_globals'):
            tags.extend(['pickle_dangerous_global', 'pickle_callable_reference'])
        if _analysis_tuple_field(analysis, 'reduce_chains'):
            tags.extend(['pickle_reduce_opcode', 'pickle_callable_reference'])
        if _analysis_bool_field(analysis, 'has_exec_chain'):
            tags.extend([
                'pickle_reduce_opcode',
                'pickle_callable_reference',
                'pickle_dangerous_global',
                'script_execution',
                'process_exec',
            ])
            ext = get_scan_extension(path) if path is not None else ''
            path_text = _path_context_text(path)
            if ext in RENPY_PICKLE_EXTENSIONS or 'renpy' in path_text:
                tags.extend(['renpy', 'renpy_script'])
            if ext == '.rpa':
                tags.extend(['pickle_file_load_context', 'save_archive_access'])
            _append_trigger_context_failure_tags(tags, analysis, path)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        tags.extend(failure_tags_for_stage('pickle_opcode_graph_tags', error, context=path))
    return unify_pickle_detection_tags(tags, path=path)


__all__ = ('pickle_opcode_graph_tags',)
