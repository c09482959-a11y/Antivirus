"""Scanner-owned pickle opcode category sets."""
from __future__ import annotations

LITERAL_OPCODES = frozenset({'BINBYTES', 'SHORT_BINBYTES', 'BINBYTES8', 'BYTEARRAY8', 'BINUNICODE', 'SHORT_BINUNICODE', 'BINUNICODE8', 'UNICODE', 'STRING'})
MEMO_PUT_OPCODES = frozenset({'BINPUT', 'LONG_BINPUT', 'PUT'})
MEMO_GET_OPCODES = frozenset({'BINGET', 'LONG_BINGET', 'GET'})
REDUCE_OPCODES = frozenset({'REDUCE', 'BUILD', 'OBJ', 'NEWOBJ', 'NEWOBJ_EX', 'INST'})

__all__ = (
    'LITERAL_OPCODES',
    'MEMO_GET_OPCODES',
    'MEMO_PUT_OPCODES',
    'REDUCE_OPCODES',
)
