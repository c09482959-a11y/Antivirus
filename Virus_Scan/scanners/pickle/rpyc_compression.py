"""Scanner-owned RPYC compressed byte-view expansion for pickle analysis."""
from __future__ import annotations

from Virus_Scan.runtime.api import is_programmer_error
from Virus_Scan.scanners.contracts import scanner_contract_join, scanner_contract_text
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.payload_decode import expand_payload_decoder_chain

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError,
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_DECODE_MAX_DECODED_BYTES = _PICKLE_POLICY.decode_max_decoded_bytes
PICKLE_DECODE_MAX_OFFSETS = _PICKLE_POLICY.decode_max_offsets


def _compressed_stream_starts(data: object) -> object:
    starts = []
    for sig in (b'x\x01', b'x^', b'x\x9c', b'x\xda', b'\x1f\x8b'):
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx < 0:
                break
            starts.append((sig, idx))
            if len(starts) >= PICKLE_DECODE_MAX_OFFSETS:
                return starts
            start = idx + 1
    return starts


def _pickle_compressed_input(value: object) -> tuple[bytes, object, str]:
    data = b''
    starts: object = ()
    status = ''
    try:
        if value is None:
            data = b''
        elif type(value) is bytes:
            data = value
        elif type(value) is bytearray:
            data = bytes(value)
        elif type(value) is memoryview:
            data = value.tobytes()
        else:
            raise ValueError('unsafe_pickle_compressed_view_input_rejected')
        starts = _compressed_stream_starts(data)
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        if is_programmer_error(exc):
            raise
        status = 'pickle_compressed_offset_scan_failure'
        starts = (('pickle_compressed_offset_scan_failure', 0),)
        data = b'pickle_compressed_offset_scan_failure'
    return data, starts, status


def _iter_expanded_compressed_views(
    data: bytes,
    starts: object,
    kind_text: str,
) -> object:
    for _signature, offset in starts[:PICKLE_DECODE_MAX_OFFSETS]:
        try:
            end = min(len(data), offset + PICKLE_DECODE_MAX_DECODED_BYTES)
            chunk = data[offset:end]
            for payload, expanded_name in expand_payload_decoder_chain(
                chunk,
                encoding_hint=scanner_contract_join(kind_text, '@', int.__str__(offset)),
            ):
                yield expanded_name, payload[:PICKLE_DECODE_MAX_DECODED_BYTES]
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
            if is_programmer_error(exc):
                raise


def _iter_pickle_compressed_views(b: object, kind_prefix: object = 'rpyc') -> object:
    kind_text = scanner_contract_text(kind_prefix, replacement='rpyc')
    data, starts, status = _pickle_compressed_input(b)
    if status:
        yield scanner_contract_join(kind_text, '+compressed_scan_failure'), data
        return
    yield from _iter_expanded_compressed_views(data, starts, kind_text)


__all__ = ('_iter_pickle_compressed_views',)
