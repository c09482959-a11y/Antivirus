"""Scanner-owned pickle literal payload record decoding."""
from __future__ import annotations

import hashlib

from Virus_Scan.runtime.api import is_programmer_error
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.payload_decode import decoded_payload_records_from_bytes, safe_decode_payloads
from Virus_Scan.scanners.pickle.literals import PickleFailureRequest, _pickle_failure_record

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError,
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_DECODE_MAX_DECODED_BYTES = _PICKLE_POLICY.decode_max_decoded_bytes
PICKLE_DECODE_MIN_PAYLOAD_BYTES = _PICKLE_POLICY.decode_min_payload_bytes
_PICKLE_LITERAL_PRINTABLE_BYTES = frozenset((9, 10, 13)) | frozenset(range(32, 127))
_PICKLE_LITERAL_TEXT_MIN_RATIO = 0.85


def _literal_record_value(rec: object, key: object, default: object = None) -> object:
    items = no_hook_mapping_items(rec, allow_dict_subclass=True)
    if items is None:
        return default
    values = {item_key: item_value for item_key, item_value in items if type(item_key) is str}
    return values.get(key, default)

def _literal_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_pickle_literal_record_text',
        unsupported_reason='unsafe_pickle_literal_record_text_rejected',
    )
    return '' if reason else text


def _decode_printable_ratio(data: object) -> object:
    sample = bytes(data or b'')[:4096]
    if not sample:
        return 0.0
    printable = sum(1 for byte in sample if byte in _PICKLE_LITERAL_PRINTABLE_BYTES)
    return printable / max(1, len(sample))

def _canonical_literal_records(payload: object, text_view: object) -> object:
    records = list(decoded_payload_records_from_bytes(payload, encoding_hint='pickle_literal', include_raw=True))
    if text_view and _decode_printable_ratio(payload) >= _PICKLE_LITERAL_TEXT_MIN_RATIO:
        records.extend(safe_decode_payloads(text_view, max_depth=2))
    return records


def _literal_payload_and_text(raw: object) -> object:
    if type(raw) is str:
        return raw.encode('latin1', errors='ignore'), raw
    if type(raw) is bytes:
        payload = raw
    elif type(raw) is bytearray:
        payload = bytes(raw)
    elif type(raw) is memoryview:
        payload = raw.tobytes()
    else:
        raise ValueError('unsafe_pickle_literal_input_rejected')
    return payload, payload.decode('latin1', errors='ignore')


def _project_literal_record(rec: object, payload: object, key: object) -> object:
    text = _literal_text(_literal_record_value(rec, 'text', ''))
    raw_magic = _literal_text(_literal_record_value(rec, 'binary_magic', ''))
    return {
        'encoding': _literal_text(_literal_record_value(rec, 'encoding', '')) or 'pickle_literal',
        'text': text[:PICKLE_DECODE_MAX_DECODED_BYTES],
        'byte_len': _literal_record_value(rec, 'byte_len') or len(payload),
        'sha256': key,
        'binary_magic': raw_magic,
        'failure_tags': _literal_record_value(rec, 'failure_tags', []),
        'failure_evidence': _literal_record_value(rec, 'failure_evidence', []),
    }


def _try_decode_pickle_literal(raw: object) -> object:
    """Return decoded records from a pickle literal byte/string object."""
    out = []
    try:
        if raw is None:
            return out
        payload, text_view = _literal_payload_and_text(raw)
        if len(payload) < PICKLE_DECODE_MIN_PAYLOAD_BYTES:
            return out
        payload = payload[:PICKLE_DECODE_MAX_DECODED_BYTES]
        seen = set()
        for rec in _canonical_literal_records(payload, text_view):
            if _literal_record_value(rec, 'failure_tags'):
                out.append(rec)
                continue
            key = _literal_text(_literal_record_value(rec, 'sha256', '')) or hashlib.sha256(
                _literal_text(_literal_record_value(rec, 'text', '')).encode('utf-8', errors='ignore')
            ).hexdigest()
            if key in seen:
                continue
            seen.add(key)
            if _literal_text(_literal_record_value(rec, 'text', '')) or _literal_text(_literal_record_value(rec, 'binary_magic', '')):
                out.append(_project_literal_record(rec, payload, key))
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        if is_programmer_error(exc):
            raise
        out.append(_pickle_failure_record(PickleFailureRequest('pickle_literal_decode', exc, encoding='pickle_literal')))
    return out


__all__ = ('_try_decode_pickle_literal',)
