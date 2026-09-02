"""Scanner-owned pickle memo stack helpers."""
from __future__ import annotations

from Virus_Scan.runtime.api import record_suppressed_failure

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


def memoize_stack_value(memo: object, stack: object, arg: object) -> object:
    try:
        if stack:
            memo[int(arg)] = stack[-1]
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc


def append_memo_value(stack: object, memo: object, arg: object) -> object:
    try:
        stack.append(memo.get(int(arg), ''))
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS:
        stack.append('')


__all__ = ('append_memo_value', 'memoize_stack_value')
