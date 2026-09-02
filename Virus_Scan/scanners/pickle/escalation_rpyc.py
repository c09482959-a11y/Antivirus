"""RPYC/RPYB view hints for pickle fast escalation."""
from __future__ import annotations

from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scanners.contracts import scanner_contract_join, scanner_contract_text, scanner_failure_evidence_tags
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.pickle.escalation_base64 import _pickle_fast_protocol_hint
from Virus_Scan.scanners.pickle.escalation_context import PICKLE_FAST_EXEC_TEXT, _pickle_fast_text_has_pickle_context
from Virus_Scan.scanners.pickle.rpyc_views import _iter_rpyc_pickle_byte_views

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_FAST_ESCALATION_MAX_BYTES = _PICKLE_POLICY.fast_escalation_max_bytes
PICKLE_DECODE_MAX_OFFSETS = _PICKLE_POLICY.decode_max_offsets
rpyc_exts = frozenset(('.rpyc', '.rpyb', '.rpymc'))


def _pickle_fast_rpyc_view_hints(data: object, path: object, ext: object) -> object:
    protocol_hint = False
    dangerous_text = False
    exec_text = False
    hits = []
    tags = []
    if ext not in rpyc_exts:
        return protocol_hint, dangerous_text, exec_text, hits, tags
    try:
        views = list(_iter_rpyc_pickle_byte_views(data, path=path))[:PICKLE_DECODE_MAX_OFFSETS]
        for view_kind, view_blob in views:
            if view_kind == 'raw':
                continue
            view_kind_text = scanner_contract_text(view_kind, replacement='rpyc_view')
            view_text = bytes(view_blob[:PICKLE_FAST_ESCALATION_MAX_BYTES]).decode('latin1', errors='ignore').lower()
            if _pickle_fast_protocol_hint(view_blob):
                protocol_hint = True
                hits.append(scanner_contract_join(view_kind_text, '_pickle_protocol_hint'))
                tags.extend(['rpyc_decoded_stream_inspected', 'pickle_deep_scan_escalated', 'strict_fast_prefilter_hit'])
            if _pickle_fast_text_has_pickle_context(view_text):
                dangerous_text = True
                hits.append(scanner_contract_join(view_kind_text, '_pickle_text_hint'))
                tags.extend(['rpyc_decoded_stream_inspected', 'pickle_deserialization_context', 'pickle_deep_scan_escalated', 'strict_fast_prefilter_hit'])
            if any((needle in view_text for needle in PICKLE_FAST_EXEC_TEXT)):
                exec_text = True
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        tags.extend(scanner_failure_evidence_tags(
            'pickle',
            'pickle_fast_rpyc_view_hint',
            exc,
            ['pickle_fast_rpyc_view_hint_error', 'pickle_failure_evidence_recorded'],
            input_path=path,
            state='degraded',
            error_category='pickle_fast_rpyc_hint_failure',
            error_source='pickle.escalation_rpyc._pickle_fast_rpyc_view_hints',
            file_type='renpy_pickle',
        ))
        hits.append('pickle_fast_rpyc_view_hint_error')
        try:
            record_suppressed_failure('suppressed_exception', exc, domain='runtime')
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as reporting_exc:
            _ = reporting_exc
    return protocol_hint, dangerous_text, exec_text, hits, tags


__all__ = ('_pickle_fast_rpyc_view_hints',)
