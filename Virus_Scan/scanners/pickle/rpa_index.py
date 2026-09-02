"""Scanner-owned Ren'Py RPA index/header byte-view helpers for pickle scanning.

This module owns only inert RPA header/index decoding. It never executes archive
contents or imports Ren'Py runtime code.
"""
from __future__ import annotations

import io
import pickle

from Virus_Scan.scanners.config.loader import load_archive_policy_snapshot
from Virus_Scan.scanners.payload_decode import expand_payload_decoder_chain

PLR2004N3 = 3
PLR2004N512 = 512

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
_ARCHIVE_POLICY = load_archive_policy_snapshot()
RPA_INDEX_MAX_BYTES = _ARCHIVE_POLICY.rpa_index_max_bytes
RPA_MEMBER_MAX_BYTES = _ARCHIVE_POLICY.rpa_member_max_bytes
RPA_MEMBER_MAX_COUNT = _ARCHIVE_POLICY.rpa_member_max_count


class _RPARestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module: object, name: object) -> object:
        del module, name
        raise pickle.UnpicklingError('RPA index GLOBAL/class loading blocked')


def _safe_load_rpa_index(index_blob: object) -> object:
    try:
        return _RPARestrictedUnpickler(io.BytesIO(index_blob)).load()
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
        return {'__rpa_index_failure__': []}


def parse_rpa_header(blob: object) -> object:
    nl = blob.find(b'\n')
    if nl <= 0 or nl > PLR2004N512:
        return None
    header = blob[:nl].decode('ascii', errors='ignore').strip().split()
    if len(header) < 2:
        return None
    version = header[0]
    index_offset = int(header[1], 16)
    key = int(header[2], 16) if len(header) >= PLR2004N3 else 0
    if index_offset <= 0 or index_offset >= len(blob):
        return None
    return version, index_offset, key


def decode_rpa_index_blob(blob: object, index_offset: object) -> object:
    for expanded, _expanded_name in expand_payload_decoder_chain(blob[index_offset:], encoding_hint='rpa_index'):
        if expanded:
            return bytes(expanded[:RPA_INDEX_MAX_BYTES])
    return b''


__all__ = (
    'RPA_INDEX_MAX_BYTES',
    'RPA_MEMBER_MAX_BYTES',
    'RPA_MEMBER_MAX_COUNT',
    '_safe_load_rpa_index',
    'decode_rpa_index_blob',
    'parse_rpa_header',
)
