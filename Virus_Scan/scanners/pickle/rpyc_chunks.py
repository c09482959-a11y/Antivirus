"""Scanner-owned RENPY RPC chunk parsing and container magic policy."""
from __future__ import annotations

from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.pickle.rpyc_chunk_parsing import (
    renpy_rpc_bytes,
    renpy_rpc_chunk_from_line,
    renpy_rpc_header_boundary,
)

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
_RENPY_RPC_HEADER_MAX_BYTES = 65536
_RENPY_RPC_CHUNK_TABLE_MIN_FIELDS = 3

def _renpy_rpc_magics() -> object:
    return (b'RENPY RPC', b'RENPY RPC2', b'RENPY RPC3', b'RENPY RPC4')



def _iter_renpy_rpc_chunks(value: object) -> object:
    """Parse RENPY RPC2/RPC3/RPC4 chunk tables: '<slot> <offset> <length>'."""
    try:
        data, data_status = renpy_rpc_bytes(value, PICKLE_SCAN_RECOVERABLE_EXCEPTIONS)
        if data_status or data is None:
            yield ('rpyc_rpc_parse_failure', b'pickle_rpc_parse_failure')
            return
        if not data.startswith(_renpy_rpc_magics()):
            return
        boundary = renpy_rpc_header_boundary(data, _RENPY_RPC_HEADER_MAX_BYTES)
        if boundary is None:
            return
        header_end, separator_length = boundary
        header = data[:header_end].decode('ascii', errors='ignore')
        for line in header.splitlines()[1:]:
            record, _record_status = renpy_rpc_chunk_from_line(
                data,
                line,
                _RENPY_RPC_CHUNK_TABLE_MIN_FIELDS,
                PICKLE_DECODE_MAX_DECODED_BYTES,
                PICKLE_SCAN_RECOVERABLE_EXCEPTIONS,
            )
            if record is not None:
                yield record
        tail = data[
            header_end + separator_length:
            header_end + separator_length + PICKLE_DECODE_MAX_DECODED_BYTES
        ]
        if tail:
            yield ('rpyc_rpc_tail', tail)
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
        yield ('rpyc_rpc_parse_failure', b'pickle_rpc_parse_failure')


def _pickle_container_magic_status(blob: object) -> object:
    try:
        if blob is None:
            head = b''
        elif type(blob) is bytes:
            head = blob[:64]
        elif type(blob) is bytearray:
            head = bytes(blob[:64])
        elif type(blob) is memoryview:
            head = blob.tobytes()[:64]
        else:
            return 'probe_error'
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
        return 'probe_error'
    else:
        return 'present' if head.startswith((b'RPA-', *_renpy_rpc_magics())) else 'absent'


def _pickle_container_magic_present(blob: object) -> object:
    return _pickle_container_magic_status(blob) == 'present'


__all__ = ('_iter_renpy_rpc_chunks', '_pickle_container_magic_present', '_pickle_container_magic_status')
