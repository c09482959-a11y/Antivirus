"""Scanner-owned pickle fast-escalation prefilter."""
from __future__ import annotations

from Virus_Scan.scanners.contracts import scanner_failure_evidence_tags
from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.pickle.escalation_base64 import (
    _pickle_fast_base64_protocol_hint,
    _pickle_fast_base64_status,
    _pickle_fast_protocol_hint,
)
from Virus_Scan.scanners.pickle.escalation_context import (
    _pickle_fast_source_escalation,
    _pickle_fast_text_has_exec_context,
    _pickle_fast_text_has_pickle_context,
)
from Virus_Scan.scanners.pickle.escalation_io import (
    _pickle_fast_apply_outcome,
    _pickle_fast_empty_info,
    _pickle_fast_path_info,
    _pickle_fast_prefilter_error,
    _pickle_fast_read_sample,
    PICKLE_FAST_READ_FAILURE,
    _pickle_fast_text_from_data,
)
from Virus_Scan.scanners.pickle.escalation_rpyc import _pickle_fast_rpyc_view_hints

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_FAST_ESCALATION_MAX_BYTES = _PICKLE_POLICY.fast_escalation_max_bytes
PICKLE_FAST_B64_SAMPLE_MAX = _PICKLE_POLICY.fast_b64_sample_max
PICKLE_FAST_RENPY_EXTS = frozenset(_PICKLE_POLICY.renpy_extensions)
PICKLE_DECODE_MAX_OFFSETS = _PICKLE_POLICY.decode_max_offsets


def _pickle_fast_owned_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_pickle_fast_text',
        unsupported_reason='unsafe_pickle_fast_text_rejected',
    )
    return '' if reason else text


def _pickle_fast_merge_rpyc_hints(data: object, path: object, ext: object, protocol_hint: object, dangerous_text: object, exec_text: object, hits: object, tags: object) -> object:
    vh_protocol, vh_danger, vh_exec, vh_hits, vh_tags = _pickle_fast_rpyc_view_hints(data, path, ext)
    hits.extend(vh_hits)
    tags.extend(vh_tags)
    return protocol_hint or vh_protocol, dangerous_text or vh_danger, exec_text or vh_exec


def _pickle_fast_record_text_outcomes(path: object, ext: object, low: object, protocol_hint: object, dangerous_text: object, exec_text: object, b64_pickle: object, malformed_b64: object, hits: object, tags: object) -> object:
    if protocol_hint:
        hits.append('pickle_protocol_hint')
        tags.extend(['pickle_fast_protocol_hint', 'pickle_deep_scan_escalated', 'strict_fast_prefilter_hit'])
    if b64_pickle:
        hits.append('pickle_base64_protocol_hint')
        tags.extend(['pickle_fast_base64_protocol_hint', 'pickle_deep_scan_escalated', 'payload_decode_candidate', 'encoded_payload_candidate', 'strict_fast_prefilter_hit'])
    elif malformed_b64 and ('base64' in low or ext in {'.rpy', '.rpym', '.rpyc', '.rpyb', '.rpymc', '.rpa'}):
        hits.append('pickle_malformed_base64_candidate')
        tags.extend(scanner_failure_evidence_tags(
            'pickle', 'pickle_fast_malformed_base64', 'base64 candidate failed strict decode',
            ['pickle_malformed_base64_candidate', 'payload_decode_failed'], input_path=path,
            state='malformed', error_category='malformed_payload_decode'))
    if dangerous_text:
        hits.append('pickle_dangerous_text_hint')
        tags.extend(['pickle_fast_text_hint', 'pickle_deserialization_context', 'pickle_deep_scan_escalated', 'strict_fast_prefilter_hit'])
    if (protocol_hint or dangerous_text or b64_pickle) and exec_text:
        hits.append('pickle_exec_context_hint')
        tags.extend(['pickle_fast_exec_context', 'pickle_deep_scan_escalated', 'strict_fast_prefilter_hit'])
    if _pickle_fast_source_escalation(ext, low, exec_text):
        hits.append('rpy_pickle_source_escalation')
        tags.extend(['pickle_source_escalation', 'pickle_deep_scan_escalated', 'pickle_deserialization_context', 'strict_fast_prefilter_hit'])


def pickle_fast_escalation_prefilter(path: object, data: object = None, text: object = None) -> object:
    """Return lightweight tags/hits that force deep pickle analysis."""
    info = _pickle_fast_empty_info()
    try:
        ext, name_l = _pickle_fast_path_info(path)
        if ext not in PICKLE_FAST_RENPY_EXTS and not any((needle in name_l for needle in ('.rpa', '.rpyc', '.rpyb', 'pickle'))):
            return info
        if data is None:
            data = _pickle_fast_read_sample(path, ext, info)
        if data is PICKLE_FAST_READ_FAILURE:
            return info
        if data is None:
            source = b''
        elif type(data) is bytes:
            source = data
        elif type(data) is bytearray:
            source = bytes(data)
        else:
            raise TypeError("unsafe_pickle_fast_data_rejected")
        data = bytes(source[:PICKLE_FAST_ESCALATION_MAX_BYTES])
        if text is None:
            text = _pickle_fast_text_from_data(data, path, info)
        low = _pickle_fast_owned_text(text).lower()
        hits: list[str] = []
        tags: list[str] = []
        protocol_hint = _pickle_fast_protocol_hint(data)
        dangerous_text = _pickle_fast_text_has_pickle_context(low)
        exec_text = _pickle_fast_text_has_exec_context(low)
        b64_pickle, malformed_b64 = _pickle_fast_base64_status(text)
        protocol_hint, dangerous_text, exec_text = _pickle_fast_merge_rpyc_hints(
            data, path, ext, protocol_hint, dangerous_text, exec_text, hits, tags)
        _pickle_fast_record_text_outcomes(
            path, ext, low, protocol_hint, dangerous_text, exec_text, b64_pickle, malformed_b64, hits, tags)
        return _pickle_fast_apply_outcome(info, ext, data, hits, tags)
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        return _pickle_fast_prefilter_error(info, path, exc)


__all__ = (
    '_pickle_fast_base64_protocol_hint',
    '_pickle_fast_base64_status',
    '_pickle_fast_protocol_hint',
    'pickle_fast_escalation_prefilter',
)
