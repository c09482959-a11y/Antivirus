"""Scanner-owned pickle opcode state facade.

Concrete ownership is split into bounded opcode_* modules. This facade preserves
the existing scanner-internal import surface without implementing behavior.
"""
from __future__ import annotations

from Virus_Scan.scanners.pickle.opcode_history import record_opcode_history
from Virus_Scan.scanners.pickle.opcode_memo import append_memo_value, memoize_stack_value
from Virus_Scan.scanners.pickle.opcode_reduce import append_reduce_chain
from Virus_Scan.scanners.pickle.opcode_sets import LITERAL_OPCODES, MEMO_GET_OPCODES, MEMO_PUT_OPCODES, REDUCE_OPCODES
from Virus_Scan.scanners.pickle.opcode_stack import append_global_reference, append_literal_opcode, append_stack_global_reference
from Virus_Scan.scanners.pickle.opcode_summary import dedupe_literal_fragments, dedupe_summary_lists, new_opcode_summary

__all__ = (
    'LITERAL_OPCODES',
    'MEMO_GET_OPCODES',
    'MEMO_PUT_OPCODES',
    'REDUCE_OPCODES',
    'append_global_reference',
    'append_literal_opcode',
    'append_memo_value',
    'append_reduce_chain',
    'append_stack_global_reference',
    'dedupe_literal_fragments',
    'dedupe_summary_lists',
    'memoize_stack_value',
    'new_opcode_summary',
    'record_opcode_history',
)
