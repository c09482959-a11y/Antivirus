"""Scanner-owned pickle opcode summary initialization and dedupe."""
from __future__ import annotations

from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot

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
PICKLE_LITERAL_JOIN_MAX = _PICKLE_POLICY.literal_join_max


def _summary_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_pickle_opcode_summary_text',
        unsupported_reason='unsafe_pickle_opcode_summary_text_rejected',
    )
    return '' if reason else text


def new_opcode_summary() -> object:
    return {
        'valid_pickle': False,
        'offsets': [],
        'opcodes': [],
        'globals': [],
        'dangerous_globals': [],
        'reduce_chains': [],
        'trigger_windows': [],
        'literal_fragments': [],
        'has_reduce': False,
        'has_stack_global': False,
        'has_build': False,
        'has_exec_chain': False,
        'errors': 0,
    }


def dedupe_summary_lists(summary: object) -> object:
    for key in ('offsets', 'opcodes', 'globals', 'dangerous_globals'):
        try:
            seen = set(); out = []
            for item in summary.get(key, []):
                sx = _summary_text(item)
                if sx not in seen:
                    seen.add(sx); out.append(item)
            summary[key] = out
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_reporting_exc:
                _ = _umige_reporting_exc
    return summary


def dedupe_literal_fragments(summary: object) -> object:
    try:
        seen = set(); frags = []
        for frag in summary.get('literal_fragments', []):
            fs = _summary_text(frag)
            if fs not in seen:
                seen.add(fs); frags.append(fs)
            if len(frags) >= PICKLE_LITERAL_JOIN_MAX:
                break
        summary['literal_fragments'] = frags
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    return summary


__all__ = (
    'dedupe_literal_fragments',
    'dedupe_summary_lists',
    'new_opcode_summary',
)
