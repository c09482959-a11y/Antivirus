"""Scanner-owned pickle literal and fragment payload decoding helpers."""
from __future__ import annotations

import hashlib
import re

from Virus_Scan.runtime.api import is_programmer_error
from Virus_Scan.scanners.config.loader import load_payload_policy_snapshot, load_pickle_policy_snapshot
from Virus_Scan.scanners.payload_decode import safe_decode_payloads
from Virus_Scan.scanners.pickle.failure_records import PickleFailureRequest, pickle_failure_record as _pickle_failure_record
from Virus_Scan.scanners.pickle.literal_text import pickle_literal_text as _pickle_literal_text
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_mapping_items_status, no_hook_sequence_items, no_hook_text
PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError)
_PICKLE_POLICY = load_pickle_policy_snapshot()
_PAYLOAD_POLICY = load_payload_policy_snapshot()
PICKLE_DECODE_MAX_DECODED_BYTES = _PICKLE_POLICY.decode_max_decoded_bytes
PICKLE_FRAGMENT_MIN_B64_CHARS = _PICKLE_POLICY.fragment_min_b64_chars
PICKLE_LITERAL_JOIN_MAX = _PICKLE_POLICY.literal_join_max
DECODE_LAYER_MAX_TEXT_BYTES = _PAYLOAD_POLICY.max_text_bytes
DECODE_LAYER_MAX_CANDIDATES = _PAYLOAD_POLICY.max_candidates
_PICKLE_LITERAL_STRING_CONVERSION_FAILED = 'pickle literal string conversion failed'


def _raise_pickle_literal_string_conversion_failed(cause: BaseException) -> None:
    raise ValueError(_PICKLE_LITERAL_STRING_CONVERSION_FAILED) from cause

def _pickle_literal_mapping_get(mapping: object, key: object, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and str.__str__(item_key) == key:
            return item_value
    return default


def _pickle_literal_mapping_key(items: object, key: object, default: object = None) -> object:
    for item_key, item_value in items:
        if type(item_key) is str and str.__str__(item_key) == key:
            return item_value
    return default


def _pickle_arg_to_bytes(arg: object) -> object:
    if arg is None:
        return b''
    if isinstance(arg, bytes):
        return arg
    if isinstance(arg, bytearray):
        return bytes(arg)
    if isinstance(arg, str):
        return arg.encode('latin1', errors='ignore')
    text, text_reason = no_hook_text(
        arg,
        missing_reason="missing_pickle_arg_bytes",
        unsupported_reason="unsafe_pickle_arg_bytes_rejected",
    )
    if text_reason:
        _raise_pickle_literal_string_conversion_failed(TypeError(text_reason))
    return text.encode('latin1', errors='ignore')


def _pickle_arg_to_text_status(arg: object) -> object:
    """Return explicit pickle argument text conversion status."""
    try:
        if isinstance(arg, bytes):
            return ('text', arg.decode('latin1', errors='ignore'))
        if isinstance(arg, bytearray):
            return ('text', bytes(arg).decode('latin1', errors='ignore'))
        text, reason = no_hook_text(
            arg,
            missing_reason="missing_pickle_arg_text",
            unsupported_reason="unsafe_pickle_arg_text_rejected",
        )
        if reason:
            return ('decode_error', TypeError(reason))
        return ('text', text)
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        return ('decode_error', exc)


def _pickle_arg_to_text(arg: object) -> object:
    status, value = _pickle_arg_to_text_status(arg)
    if status == 'decode_error':
        raise ValueError('pickle argument text conversion failed') from (value if isinstance(value, BaseException) else TypeError(str(value)))
    if type(value) is str:
        return value
    exception_message = 'pickle argument text conversion failed'
    raise ValueError(exception_message) from TypeError('pickle_argument_text_not_text')


def _fragment_candidates(frags: object) -> object:
    candidates = []
    for i, frag in enumerate(frags[:PICKLE_LITERAL_JOIN_MAX]):
        candidates.append(('pickle_fragment', frag))
        joined = ''
        for j in range(i, min(len(frags), i + 8)):
            joined += re.sub('\\s+', '', frags[j])
            if len(joined) >= PICKLE_FRAGMENT_MIN_B64_CHARS:
                candidates.append(('pickle_fragment_joined', joined))
            if len(joined) > DECODE_LAYER_MAX_TEXT_BYTES * 2:
                break
    return candidates


def _decode_fragment_candidates(candidates: object) -> object:
    out = []
    seen = set()
    for kind, cand in candidates[:DECODE_LAYER_MAX_CANDIDATES * 2]:
        cand_text = _pickle_literal_text(cand)
        compact = re.sub('\\s+', '', cand_text)
        if len(compact) < PICKLE_FRAGMENT_MIN_B64_CHARS:
            continue
        key = hashlib.sha256((kind + ':' + compact[:256]).encode('utf-8', errors='ignore')).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        for rec in no_hook_sequence_items(safe_decode_payloads(compact, max_depth=2)):
            if _pickle_literal_mapping_get(rec, 'failure_tags'):
                rec['fragmented'] = True
                out.append(rec)
                continue
            if _pickle_literal_mapping_get(rec, 'text') or _pickle_literal_mapping_get(rec, 'binary_magic'):
                rec['fragmented'] = True
                if not _pickle_literal_mapping_get(rec, 'encoding'):
                    rec['encoding'] = kind
                out.append(rec)
    return out


def _iter_pickle_fragment_decode_records_from_analysis(analysis: object) -> object:
    """Decode fragmented pickle string literals through scanner payload authority."""
    try:
        analysis_items, analysis_reason = no_hook_mapping_items_status(analysis)
        if analysis_items is None:
            return [_pickle_failure_record(PickleFailureRequest('pickle_fragment_decode_records', TypeError(analysis_reason), encoding='pickle_fragment_decode_failure'))]
        raw_frags = _pickle_literal_mapping_key(analysis_items, 'literal_fragments', ())
        frags = []
        for item in no_hook_sequence_items(raw_frags):
            item_text = _pickle_literal_text(item)
            if item_text.strip():
                frags.append(item_text)
        if not frags:
            return []
        return _decode_fragment_candidates(_fragment_candidates(frags))
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as e:
        if is_programmer_error(e):
            raise
        return [_pickle_failure_record(PickleFailureRequest('pickle_fragment_decode_records', e, encoding='pickle_fragment_decode_failure'))]

def pickle_fragment_decode_records_from_analysis(analysis: object) -> object:
    """Public scanner-owned pickle fragment payload decoding contract."""
    return list(_iter_pickle_fragment_decode_records_from_analysis(analysis) or [])

__all__ = ('PickleFailureRequest', '_iter_pickle_fragment_decode_records_from_analysis', '_pickle_arg_to_bytes', '_pickle_arg_to_text', '_pickle_arg_to_text_status', '_pickle_failure_record', 'pickle_fragment_decode_records_from_analysis')
