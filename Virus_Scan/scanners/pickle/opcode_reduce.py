"""Scanner-owned REDUCE/BUILD pickle transition evidence."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.scanners.pickle.global_references import _pickle_global_text, _pickle_is_dangerous_callable_global

@dataclass(frozen=True, slots=True)
class PickleReduceRequest:
    summary: object
    stack: object
    last_callable: object
    name: object
    offset: object
    position: object
    op_history: object

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

def _pickle_reduce_position(value: object) -> object:
    number, reason = no_hook_exact_nonnegative_int(
        value,
        default=0,
        reason='unsafe_pickle_reduce_position_rejected',
    )
    return 0 if reason else number

def append_reduce_chain(request: PickleReduceRequest) -> object:
    if request.name == 'REDUCE':
        request.summary['has_reduce'] = True
    if request.name == 'BUILD':
        request.summary['has_build'] = True
    callable_candidates = []
    if request.last_callable is not None:
        callable_candidates.append(request.last_callable)
    callable_candidates.extend(request.summary.get('dangerous_globals', [])[-4:])
    for cand in callable_candidates:
        c, reason = _pickle_global_text(cand)
        if reason:
            continue
        if _pickle_is_dangerous_callable_global(c):
            position = _pickle_reduce_position(request.position)
            request.summary['reduce_chains'].append({'opcode': request.name, 'callable': c, 'stream_offset': request.offset, 'op_position': position})
            try:
                request.summary.setdefault('trigger_windows', []).append({'callable': c, 'opcode': request.name, 'stream_offset': request.offset, 'op_position': position, 'ops': list(request.op_history[-8:])})
            except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_suppressed_exc:
                try:
                    record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
                except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_reporting_exc:
                    _ = _umige_reporting_exc
            request.summary['has_exec_chain'] = True
            break
    request.stack.append('<reduce_result>')

__all__ = (
    'PickleReduceRequest',
    'append_reduce_chain',
)
