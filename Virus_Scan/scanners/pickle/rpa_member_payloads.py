"""Scanner-owned inert RPA member payload views for pickle inspection."""
from __future__ import annotations

import pickle

from Virus_Scan.contracts.no_hook_materialization import exact_int_or_none, no_hook_mapping_items, no_hook_text
from Virus_Scan.contracts.path_identity import path_identity
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.pickle.rpa_index import (
    RPA_MEMBER_MAX_BYTES,
    RPA_MEMBER_MAX_COUNT,
    _safe_load_rpa_index,
    decode_rpa_index_blob,
    parse_rpa_header,
)

PLR2004N3 = 3

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
PICKLE_DECODE_MAX_FILE_BYTES = _PICKLE_POLICY.decode_max_file_bytes


def _rpa_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_rpa_member_text',
        unsupported_reason='unsafe_rpa_member_text_rejected',
    )
    return '' if reason else text


def _rpa_path_text(path: object) -> object:
    try:
        return path_identity(path).raw
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
        return 'rpa_path_probe_error'


def _rpa_exact_int(value: object) -> object:
    return exact_int_or_none(value)


def prepare_rpa_blob(data: object) -> object:
    if data is None:
        return b''
    if type(data) is bytes:
        return data[:PICKLE_DECODE_MAX_FILE_BYTES]
    if type(data) is bytearray:
        return bytes(data[:PICKLE_DECODE_MAX_FILE_BYTES])
    if type(data) is memoryview:
        return data.tobytes()[:PICKLE_DECODE_MAX_FILE_BYTES]
    return b'pickle_rpa_member_prepare_failure'


def member_rank(item: object) -> object:
    name = _rpa_text(item[0] if type(item) in (tuple, list) and item else '').replace('\\', '/').lower()
    if name in {'script.rpyc', 'scripts.rpyc'}:
        return (0, name)
    if name.endswith(('.rpyc', '.rpyb', '.rpymc', '.rpy')):
        return (1, name)
    return (2, name)


def iter_rpa_entry_payloads(blob: object, entries: object, key: object) -> object:
    if not isinstance(entries, (list, tuple)):
        return
    for entry in entries[:4]:
        if not isinstance(entry, (list, tuple)) or len(entry) < 2:
            continue
        raw_off = _rpa_exact_int(entry[0])
        raw_len = _rpa_exact_int(entry[1])
        if raw_off is None or raw_len is None:
            continue
        off = raw_off ^ key
        ln = raw_len ^ key
        prefix = entry[2] if len(entry) >= PLR2004N3 and isinstance(entry[2], (bytes, bytearray)) else b''
        if off < 0 or ln <= 0 or off >= len(blob):
            continue
        bounded_len = min(ln, RPA_MEMBER_MAX_BYTES)
        payload = bytes(prefix) + blob[off:min(len(blob), off + bounded_len)]
        if payload:
            yield payload, off, bounded_len


def load_rpa_member_index(blob: object) -> object:
    header = parse_rpa_header(blob)
    if header is None:
        return None
    version, index_offset, key = header
    index_blob = decode_rpa_index_blob(blob, index_offset)
    if not index_blob:
        return None
    index = _safe_load_rpa_index(index_blob)
    if not isinstance(index, dict):
        return None
    return version, key, index


def iter_rpa_member_views(blob: object, path: object = None) -> object:
    parsed = load_rpa_member_index(blob)
    if parsed is None:
        return
    version, key, index = parsed
    emitted = 0
    index_items = no_hook_mapping_items(index, allow_dict_subclass=True) or ()
    for member_name, entries in sorted(index_items, key=member_rank):
        if emitted >= RPA_MEMBER_MAX_COUNT:
            break
        name = _rpa_text(member_name).replace('\\', '/')[:512]
        for payload, off, ln in iter_rpa_entry_payloads(blob, entries, key):
            if emitted >= RPA_MEMBER_MAX_COUNT:
                break
            emitted += 1
            yield (name, payload, {
                'rpa_version': version,
                'member_offset': off,
                'member_length': ln,
                'source_file': _rpa_path_text(path),
            })


def iter_renpy_rpa_members(data: object = None, path: object = None) -> object:
    """Yield bounded RPA member byte views for pickle inspection."""
    blob = prepare_rpa_blob(data)
    if not blob.startswith(b'RPA-'):
        return
    try:
        yield from iter_rpa_member_views(blob, path=path) or ()
    except (OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError, pickle.UnpicklingError):
        yield ('__rpa_member_parse_failure__', b'pickle_rpa_member_parse_failure', {
            'failure': 'rpa_member_parse_failure',
            'source_file': _rpa_path_text(path),
        })



_iter_renpy_rpa_members = iter_renpy_rpa_members

__all__ = (
    'PICKLE_DECODE_MAX_FILE_BYTES',
    '_iter_renpy_rpa_members',
    'iter_renpy_rpa_members',
    'iter_rpa_entry_payloads',
    'iter_rpa_member_views',
    'load_rpa_member_index',
    'member_rank',
    'prepare_rpa_blob',
)
