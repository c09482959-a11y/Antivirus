"""Scanner-owned pickle protocol detection helpers.

This module owns protocol-header discovery only. It does not disassemble, load,
unpickle, import, or execute untrusted data.
"""
from __future__ import annotations

import re

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int

_PICKLE_PROTOCOL_HEADER_RE = re.compile(b'\x80[\x02\x03\x04\x05].{0,4096}(?:c|\x93|R|b)', re.DOTALL)
_PICKLE_PROTOCOL_OFFSET_RE = re.compile(b'\x80[\x02\x03\x04\x05]')
_PICKLE_PROTOCOL_PREFIXES = (b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05')


def _pickle_protocol_limit(value: object, default: object) -> object:
    number, reason = no_hook_exact_nonnegative_int(
        value,
        default=default,
        reason='unsafe_pickle_protocol_limit_rejected',
    )
    return default if reason else number


def _sample_bytes(data: bytes | bytearray | memoryview | object, max_bytes: int) -> bytes:
    """Return bounded pickle protocol sample bytes without hiding conversion failures."""
    limit = _pickle_protocol_limit(max_bytes, 0)
    if data is None:
        return b''
    if type(data) is bytes:
        return data[:limit]
    if type(data) is bytearray:
        return bytes(data[:limit])
    if type(data) is memoryview:
        return data.tobytes()[:limit]
    raise ValueError('unsafe_pickle_protocol_input_rejected')


def has_pickle_protocol_header(data: bytes | bytearray | memoryview | object, *, max_bytes: int) -> bool:
    sample = _sample_bytes(data, max_bytes)
    if not sample:
        return False
    if sample.startswith(_PICKLE_PROTOCOL_PREFIXES):
        return True
    if _PICKLE_PROTOCOL_OFFSET_RE.search(sample):
        return True
    return bool(_PICKLE_PROTOCOL_HEADER_RE.search(sample))


def pickle_protocol_offsets(data: bytes | bytearray | memoryview | object, *, max_offsets: int, max_bytes: int) -> tuple[int, ...]:
    sample = _sample_bytes(data, max_bytes)
    if not sample:
        return ()
    limit = max(1, _pickle_protocol_limit(max_offsets, 1))
    offsets: list[int] = [0]
    for match in _PICKLE_PROTOCOL_OFFSET_RE.finditer(sample):
        offset = int(match.start())
        if offset not in offsets:
            offsets.append(offset)
        if len(offsets) >= limit:
            break
    return tuple(offsets[:limit])


__all__ = ("has_pickle_protocol_header", "pickle_protocol_offsets")
