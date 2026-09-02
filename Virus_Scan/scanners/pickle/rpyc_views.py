"""Scanner-owned Ren'Py RPYC byte-view orchestration for pickle scanning."""
from __future__ import annotations

from Virus_Scan.contracts.path_identity import get_scan_extension, path_identity
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.pickle.rpyc_chunks import _iter_renpy_rpc_chunks, _pickle_container_magic_present, _pickle_container_magic_status
from Virus_Scan.scanners.pickle.rpyc_compression import _iter_pickle_compressed_views
from Virus_Scan.scanners.pickle.rpyc_emit import _iter_pickle_view_with_nested_compression, _pickle_view_emit
from Virus_Scan.scanners.pickle.rpyc_rpa_flow import iter_optional_rpa_views

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError,
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_DECODE_MAX_FILE_BYTES = _PICKLE_POLICY.decode_max_file_bytes
PICKLE_DECODE_MAX_OFFSETS = _PICKLE_POLICY.decode_max_offsets
RENPY_BYTECODE_EXTENSIONS = frozenset({'.rpyc', '.rpyb', '.rpymc', '.rpa', '.rpy', '.rpym'})


def _rpyc_input_blob(data: object) -> object:
    if data is None:
        return b''
    if type(data) is bytes:
        return data[:PICKLE_DECODE_MAX_FILE_BYTES]
    if type(data) is bytearray:
        return bytes(data[:PICKLE_DECODE_MAX_FILE_BYTES])
    if type(data) is memoryview:
        return data.tobytes()[:PICKLE_DECODE_MAX_FILE_BYTES]
    raise TypeError('unsafe_rpyc_pickle_view_input_rejected')




def _rpyc_input_result(data: object) -> tuple[bytes, str]:
    try:
        return _rpyc_input_blob(data), ''
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
        return b'rpyc_input_conversion_failure', 'rpyc_input_conversion_failure'

def _rpyc_safe_extension(path: object) -> object:
    try:
        return get_scan_extension(path) if path is not None else ''
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
        return '.scanner_ext_error'


def _renpy_like_pickle_view_status(ext: object, path: object, blob: object) -> object:
    try:
        path_text = path_identity(path).raw.lower()
        if ext in RENPY_BYTECODE_EXTENSIONS or 'renpy' in path_text:
            return True, 'path_or_extension'
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
        return False, 'path_probe_error'
    magic_status = _pickle_container_magic_status(blob)
    return magic_status == 'present', magic_status



def _iter_rpc_decompressed_views(seen: object, blob: object) -> object:
    for chunk_kind, chunk in list(_iter_renpy_rpc_chunks(blob) or [])[:PICKLE_DECODE_MAX_OFFSETS]:
        yield from _iter_pickle_view_with_nested_compression(seen, chunk_kind, chunk)
        for decode_kind, payload in _iter_pickle_compressed_views(chunk, kind_prefix=chunk_kind):
            yield from _iter_pickle_view_with_nested_compression(seen, decode_kind, payload)


def iter_rpyc_pickle_byte_views(data: object = None, path: object = None) -> object:
    """Yield bounded raw/decompressed byte views for Ren'Py bytecode pickle inspection."""
    blob, input_status = _rpyc_input_result(data)
    if input_status:
        failure_item = _pickle_view_emit(set(), input_status, blob)
        if failure_item:
            yield failure_item
        return
    if not blob:
        return
    seen = set()
    first = _pickle_view_emit(seen, 'raw', blob)
    if first:
        yield first
    ext = _rpyc_safe_extension(path)
    yield from iter_optional_rpa_views(
        seen, blob, path, ext, iter_rpyc_pickle_byte_views,
    )
    renpy_like, renpy_like_status = _renpy_like_pickle_view_status(ext, path, blob)
    if not renpy_like:
        if renpy_like_status in {'path_probe_error', 'probe_error'}:
            failure_item = _pickle_view_emit(seen, 'rpyc_container_magic_probe_failure', b'rpyc_container_magic_probe_failure')
            if failure_item:
                yield failure_item
        return
    yield from _iter_rpc_decompressed_views(seen, blob)
    for decode_kind, payload in _iter_pickle_compressed_views(blob, kind_prefix='rpyc'):
        yield from _iter_pickle_view_with_nested_compression(seen, decode_kind, payload)



_iter_rpyc_pickle_byte_views = iter_rpyc_pickle_byte_views

__all__ = (
    '_iter_pickle_compressed_views',
    '_iter_renpy_rpc_chunks',
    '_iter_rpyc_pickle_byte_views',
    '_pickle_container_magic_present',
    '_pickle_container_magic_status',
    '_renpy_like_pickle_view_status',
    'iter_rpyc_pickle_byte_views',
)
