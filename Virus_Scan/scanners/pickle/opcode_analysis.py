"""Scanner-owned pickle opcode analysis.

This module owns orchestration of non-executing pickletools opcode walks. Local
state mutation and individual opcode effects are delegated to opcode_state.py.
"""
from __future__ import annotations

import pickletools

from Virus_Scan.scanners.contracts import scanner_contract_error_message
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.pickle.global_references import (
    _pickle_canonical_global,
    _pickle_is_dangerous_callable_global,
    _pickle_is_safe_reconstruct_global,
    _pickle_is_suspicious_reference_global,
)
from Virus_Scan.scanners.pickle.literals import (
    _iter_pickle_fragment_decode_records_from_analysis,
    _pickle_arg_to_bytes,
    _pickle_arg_to_text,
    PickleFailureRequest,
    _pickle_failure_record,
    pickle_fragment_decode_records_from_analysis,
)
from Virus_Scan.scanners.pickle.opcode_history import record_opcode_history
from Virus_Scan.scanners.pickle.opcode_memo import append_memo_value, memoize_stack_value
from Virus_Scan.scanners.pickle.opcode_reduce import PickleReduceRequest, append_reduce_chain
from Virus_Scan.scanners.pickle.opcode_sets import LITERAL_OPCODES, MEMO_GET_OPCODES, MEMO_PUT_OPCODES, REDUCE_OPCODES
from Virus_Scan.scanners.pickle.opcode_stack import append_global_reference, append_literal_opcode, append_stack_global_reference
from Virus_Scan.scanners.pickle.opcode_summary import dedupe_literal_fragments, dedupe_summary_lists, new_opcode_summary
from Virus_Scan.scanners.pickle.protocol import pickle_protocol_offsets

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
PICKLE_DECODE_MAX_OFFSETS = _PICKLE_POLICY.decode_max_offsets
_PICKLE_OPCODE_INFO_TYPE = type(pickletools.opcodes[0])


def _pickle_opcode_input_blob(data: object) -> object:
    if data is None:
        return b''
    if type(data) is bytes:
        return data[:PICKLE_DECODE_MAX_FILE_BYTES]
    if type(data) is bytearray:
        return bytes(data[:PICKLE_DECODE_MAX_FILE_BYTES])
    if type(data) is memoryview:
        return data.tobytes()[:PICKLE_DECODE_MAX_FILE_BYTES]
    raise TypeError('unsafe_pickle_opcode_input_rejected')


def _pickle_opcode_name(op: object) -> object:
    if type(op) is not _PICKLE_OPCODE_INFO_TYPE:
        return ''
    name = op.name
    return name.upper() if type(name) is str else ''


def _analyze_single_pickle_stream(summary: object, blob: object, off: object, max_ops: object) -> object:
    stack = []
    memo = {}
    last_callable = ''
    op_history = []
    for op_count, (op, arg, pos) in enumerate(pickletools.genops(blob[off:]), start=1):
        if op_count > max_ops:
            break
        name = _pickle_opcode_name(op)
        record_opcode_history(op_history, name, arg, off, pos)
        summary['valid_pickle'] = True
        summary['offsets'].append(off)
        summary['opcodes'].append(name)
        if name in LITERAL_OPCODES:
            append_literal_opcode(summary, stack, arg)
        elif name in MEMO_PUT_OPCODES:
            memoize_stack_value(memo, stack, arg)
        elif name in MEMO_GET_OPCODES:
            append_memo_value(stack, memo, arg)
        elif name == 'GLOBAL':
            last_callable = append_global_reference(summary, stack, arg) or last_callable
        elif name == 'STACK_GLOBAL':
            last_callable = append_stack_global_reference(summary, stack) or last_callable
        elif name in REDUCE_OPCODES:
            append_reduce_chain(PickleReduceRequest(summary, stack, last_callable, name, off, pos, op_history))


def analyze_pickle_opcode_graph(data: object, max_ops: object = 4096) -> object:
    """Analyze pickle opcode streams without executing them."""
    summary = new_opcode_summary()
    try:
        blob = _pickle_opcode_input_blob(data)
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        summary['errors'] += 1
        summary.setdefault('error_tags', []).append('pickle_opcode_input_conversion_error')
        summary.setdefault('failure_evidence', []).append({
            'scanner': 'pickle',
            'stage': 'pickle_opcode_input_conversion',
            'state': 'malformed',
            'error_category': 'pickle_input_conversion_failure',
            'exception_type': type(exc).__name__,
            'error': scanner_contract_error_message(exc),
            'downstream_final_json_required': True,
        })
        return summary
    if not blob:
        return summary
    offsets = list(pickle_protocol_offsets(blob, max_offsets=PICKLE_DECODE_MAX_OFFSETS, max_bytes=PICKLE_DECODE_MAX_FILE_BYTES))
    seen_offsets = set()
    for off in offsets[:PICKLE_DECODE_MAX_OFFSETS]:
        if off in seen_offsets or off >= len(blob):
            continue
        seen_offsets.add(off)
        try:
            _analyze_single_pickle_stream(summary, blob, off, max_ops)
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
            summary['errors'] += 1
            summary.setdefault('error_tags', []).append('pickle_opcode_stream_parse_error')
            summary.setdefault('failure_evidence', []).append(
                _pickle_failure_record(PickleFailureRequest('pickle_opcode_stream_parse', exc, pickle_offset=off))
            )
            continue
    dedupe_summary_lists(summary)
    dedupe_literal_fragments(summary)
    return summary


__all__ = (
    '_iter_pickle_fragment_decode_records_from_analysis',
    '_pickle_arg_to_bytes',
    '_pickle_arg_to_text',
    '_pickle_canonical_global',
    '_pickle_failure_record',
    '_pickle_is_dangerous_callable_global',
    '_pickle_is_safe_reconstruct_global',
    '_pickle_is_suspicious_reference_global',
    'analyze_pickle_opcode_graph',
    'pickle_fragment_decode_records_from_analysis',
)
