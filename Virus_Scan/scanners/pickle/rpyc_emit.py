"""Scanner-owned RPYC byte-view emission and bounded nested expansion."""
from __future__ import annotations

import hashlib

from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.pickle.rpyc_compression import _iter_pickle_compressed_views

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError,
    EOFError,
    ValueError,
    TypeError,
    RuntimeError,
    KeyError,
    AttributeError,
    UnicodeError,
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_DECODE_MAX_DECODED_BYTES = _PICKLE_POLICY.decode_max_decoded_bytes


def _pickle_view_emit(seen: object, kind: object, payload: object) -> object:
    try:
        if not payload:
            return None
        payload = bytes(payload[:PICKLE_DECODE_MAX_DECODED_BYTES])
        digest_input = kind.encode('utf-8', errors='ignore') + b':' + payload[:4096]
        digest = hashlib.sha256(digest_input).hexdigest()
        if digest in seen:
            return None
        seen.add(digest)
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
        return ('pickle_view_emit_failure', b'pickle_view_emit_failure')
    else:
        return (kind, payload)


def _iter_pickle_view_with_nested_compression(seen: object, kind: object, payload: object, depth: object = 0) -> object:
    item = _pickle_view_emit(seen, kind, payload)
    if item:
        yield item
    if depth >= 1 or not payload:
        return
    conversion_failure = False
    try:
        inner = bytes(payload[:PICKLE_DECODE_MAX_DECODED_BYTES])
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
        conversion_failure = True
        inner = b'pickle_nested_payload_conversion_failure'
    if conversion_failure:
        failure_item = _pickle_view_emit(seen, kind + '+nested_payload_conversion_failure', inner)
        if failure_item:
            yield failure_item
        return
    for nested_kind, nested_payload in _iter_pickle_compressed_views(inner, kind_prefix=kind + '+nested'):
        yield from _iter_pickle_view_with_nested_compression(seen, nested_kind, nested_payload, depth + 1)


__all__ = ('_pickle_view_emit', '_iter_pickle_view_with_nested_compression')
