"""Base pickle opcode graph tag projection."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.scanners.contracts import scanner_contract_text
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.pickle.source_detection import _is_renpy_pickle_path

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
RENPY_PICKLE_EXTENSIONS = frozenset(_PICKLE_POLICY.renpy_extensions)


def _safe_scan_extension(path: object) -> object:
    try:
        return get_scan_extension(path) if path is not None else ''
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        try:
            record_suppressed_failure('suppressed_exception', exc, domain='runtime')
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as reporting_exc:
            _ = reporting_exc
    return ''


def _pickle_tag_texts(tags: object) -> object:
    out = []
    for tag in no_hook_sequence_items(tags):
        text = scanner_contract_text(tag, replacement='').strip()
        if text:
            out.append(text)
    return out


def unify_pickle_detection_tags(tags: object, path: object = None) -> object:
    """Return atomic pickle observations without reconstructing chain identity."""
    try:
        out = _pickle_tag_texts(tags)
        low = {tag_text.lower() for tag_text in out}
        if low & {
            "pickle_external_executable_reference",
            "pickle_external_script_reference",
            "pickle_external_file_reference",
        }:
            out.append("pickle_file_load_context")
        return sorted(set(out))
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
        return ["pickle_tag_normalization_failure_evidence"]


def base_opcode_graph_tags(analysis: object, path: object = None) -> object:
    tags = ['pickle_opcode_inspected', 'pickle_opcode_graph_analyzed']
    if analysis.get('globals'):
        tags.append('pickle_global_reference')
    if analysis.get('has_stack_global'):
        tags.append('pickle_stack_global')
    if analysis.get('has_reduce'):
        tags.append('pickle_reduce_opcode')
    if analysis.get('dangerous_globals'):
        tags.extend(['pickle_dangerous_global', 'pickle_callable_reference'])
    if analysis.get('reduce_chains'):
        tags.extend(['pickle_reduce_opcode', 'pickle_callable_reference'])
    if analysis.get('has_exec_chain'):
        tags.extend(['pickle_reduce_opcode', 'pickle_callable_reference', 'pickle_dangerous_global', 'script_execution', 'process_exec'])
        ext = _safe_scan_extension(path)
        if ext in RENPY_PICKLE_EXTENSIONS or _is_renpy_pickle_path(path):
            tags.extend(['renpy', 'renpy_script'])
        if ext == '.rpa':
            tags.extend(['pickle_file_load_context', 'save_archive_access'])
    return tags


__all__ = ('base_opcode_graph_tags', 'unify_pickle_detection_tags')
