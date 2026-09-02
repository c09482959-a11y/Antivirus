"""Scanner-owned bounded pickle opcode history projection."""
from __future__ import annotations

from Virus_Scan.runtime.api import record_suppressed_failure

PLR2004N12 = 12

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


def record_opcode_history(op_history: object, name: object, arg: object, off: object, pos: object) -> object:
    try:
        arg_preview = '' if arg is None else repr(arg)[:180]
        op_history.append({'opcode': name, 'arg': arg_preview, 'stream_offset': off, 'op_position': int(pos)})
        if len(op_history) > PLR2004N12:
            del op_history[:-12]
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc


__all__ = ('record_opcode_history',)
