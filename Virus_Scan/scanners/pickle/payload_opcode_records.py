"""Scanner-owned pickle opcode literal payload record iteration."""
from __future__ import annotations

import pickletools

from Virus_Scan.runtime.api import is_programmer_error
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.pickle.literals import PickleFailureRequest, _pickle_failure_record
from Virus_Scan.scanners.pickle.opcode_sets import LITERAL_OPCODES
from Virus_Scan.scanners.pickle.payload_literal_records import _try_decode_pickle_literal
from Virus_Scan.scanners.pickle.protocol import pickle_protocol_offsets

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError,
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_DECODE_MAX_FILE_BYTES = _PICKLE_POLICY.decode_max_file_bytes
PICKLE_DECODE_MAX_OBJECTS = _PICKLE_POLICY.decode_max_objects
PICKLE_DECODE_MAX_OFFSETS = _PICKLE_POLICY.decode_max_offsets
_PICKLE_OPCODE_INFO_TYPE = type(pickletools.opcodes[0])


def _pickle_payload_input_blob(data: object) -> object:
    if data is None:
        return b''
    if type(data) is bytes:
        return data[:PICKLE_DECODE_MAX_FILE_BYTES]
    if type(data) is bytearray:
        return bytes(data[:PICKLE_DECODE_MAX_FILE_BYTES])
    if type(data) is memoryview:
        return data.tobytes()[:PICKLE_DECODE_MAX_FILE_BYTES]
    raise ValueError('unsafe_pickle_payload_opcode_input_rejected')


def _pickle_payload_opcode_name(op: object) -> object:
    if type(op) is not _PICKLE_OPCODE_INFO_TYPE:
        return ''
    name = op.name
    return name if type(name) is str else ''


def _iter_pickle_offset_records(blob: bytes, offset: int) -> object:
    try:
        for count, (op, arg, _position) in enumerate(pickletools.genops(blob[offset:]), start=1):
            if count > PICKLE_DECODE_MAX_OBJECTS:
                break
            name = _pickle_payload_opcode_name(op)
            if name in LITERAL_OPCODES:
                for record in _try_decode_pickle_literal(arg):
                    record['pickle_offset'] = offset
                    record['pickle_opcode'] = name
                    yield record
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        if is_programmer_error(exc):
            raise
        yield _pickle_failure_record(PickleFailureRequest(
            'pickle_payload_opcode_decode', exc,
            encoding='pickle_opcode_payload', pickle_offset=offset,
        ))


def iter_pickle_payload_records(data: object) -> object:
    """Yield decoded records from pickle opcode literals without executing pickle."""
    try:
        blob = _pickle_payload_input_blob(data)
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        if is_programmer_error(exc):
            raise
        yield _pickle_failure_record(PickleFailureRequest(
            'pickle_payload_opcode_input', exc, encoding='pickle_opcode_payload',
        ))
        blob = b''
    if blob:
        offsets = list(pickle_protocol_offsets(
            blob, max_offsets=PICKLE_DECODE_MAX_OFFSETS, max_bytes=PICKLE_DECODE_MAX_FILE_BYTES,
        ))
        seen_offsets: set[int] = set()
        for offset in offsets:
            if offset not in seen_offsets and offset < len(blob):
                seen_offsets.add(offset)
                yield from _iter_pickle_offset_records(blob, offset)


_iter_pickle_payload_records = iter_pickle_payload_records

__all__ = ('iter_pickle_payload_records', '_iter_pickle_payload_records')
