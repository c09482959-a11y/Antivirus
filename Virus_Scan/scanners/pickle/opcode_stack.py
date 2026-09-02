"""Scanner-owned pickle stack/global reference transitions."""
from __future__ import annotations

from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.pickle.global_references import (
    _pickle_canonical_global,
    _pickle_is_dangerous_callable_global,
    _pickle_is_suspicious_reference_global,
)
from Virus_Scan.scanners.pickle.literals import _pickle_arg_to_bytes, _pickle_arg_to_text

PLR2004N3 = 3

_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_DECODE_MAX_DECODED_BYTES = _PICKLE_POLICY.decode_max_decoded_bytes


def append_literal_opcode(summary: object, stack: object, arg: object) -> object:
    b = _pickle_arg_to_bytes(arg)
    t = _pickle_arg_to_text(arg)
    if type(t) is not str:
        t = ''
    if b:
        stack.append(t or b)
    if t and PLR2004N3 <= len(t) <= PICKLE_DECODE_MAX_DECODED_BYTES:
        summary['literal_fragments'].append(t)


def append_global_reference(summary: object, stack: object, arg: object) -> object:
    g = _pickle_canonical_global(arg)
    if not g:
        return ''
    stack.append(g)
    summary['globals'].append(g)
    if _pickle_is_dangerous_callable_global(g):
        summary['dangerous_globals'].append(g)
    return g


def append_stack_global_reference(summary: object, stack: object) -> object:
    summary['has_stack_global'] = True
    name_part = stack.pop() if stack else ''
    module_part = stack.pop() if stack else ''
    g1 = _pickle_canonical_global(module_part, name_part)
    g2 = _pickle_canonical_global(name_part, module_part)
    if _pickle_is_dangerous_callable_global(g1):
        g = g1
    elif _pickle_is_dangerous_callable_global(g2):
        g = g2
    elif _pickle_is_suspicious_reference_global(g1):
        g = g1
    else:
        g = g2
    if g:
        stack.append(g)
        summary['globals'].append(g)
        if _pickle_is_dangerous_callable_global(g):
            summary['dangerous_globals'].append(g)
    return g


__all__ = (
    'append_global_reference',
    'append_literal_opcode',
    'append_stack_global_reference',
)
