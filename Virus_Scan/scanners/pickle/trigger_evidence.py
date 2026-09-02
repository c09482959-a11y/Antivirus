"""Pickle opcode trigger-window evidence projection."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items, no_hook_text
from Virus_Scan.runtime.api import record_suppressed_failure

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError
)


def _pickle_mapping_get(mapping: object, key: object, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and str.__str__(item_key) == key:
            return item_value
    return default


def _pickle_text(value: object, *, default: object = '') -> object:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_pickle_trigger_text",
        unsupported_reason="unsafe_pickle_trigger_text_rejected",
    )
    return default if reason else text.strip()


def _pickle_upper(value: object, *, default: object = 'REDUCE') -> object:
    text = _pickle_text(value, default=default)
    return text.upper() if text else default


def record_trigger_windows(analysis: object) -> object:
    try:
        trigger_windows = []
        for tw in no_hook_sequence_items(_pickle_mapping_get(analysis, 'trigger_windows', ()))[:4]:
            parts = []
            for oprec in no_hook_sequence_items(_pickle_mapping_get(tw, 'ops', ()))[-8:]:
                opname = _pickle_text(_pickle_mapping_get(oprec, 'opcode', ''))
                argtxt = _pickle_text(_pickle_mapping_get(oprec, 'arg', ''))
                posn = _pickle_text(_pickle_mapping_get(oprec, 'op_position', ''), default='unknown')
                if argtxt:
                    parts.append(posn + ':' + opname + ' ' + argtxt)
                else:
                    parts.append(posn + ':' + opname)
            if parts:
                trigger_windows.append(' | '.join(parts))
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        try:
            record_suppressed_failure('suppressed_exception', exc, domain='runtime')
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as reporting_exc:
            _ = reporting_exc
    else:
        return trigger_windows
    return []


def pickle_trigger_summaries(analysis: object) -> object:
    try:
        raw_triggers = []
        for rc in no_hook_sequence_items(_pickle_mapping_get(analysis, 'reduce_chains', ()))[:8]:
            callable_name = _pickle_text(_pickle_mapping_get(rc, 'callable', ''))
            opcode_name = _pickle_upper(_pickle_mapping_get(rc, 'opcode', 'REDUCE'))
            if callable_name:
                stream_offset = _pickle_text(_pickle_mapping_get(rc, 'stream_offset', ''), default='unknown')
                op_position = _pickle_text(_pickle_mapping_get(rc, 'op_position', ''), default='unknown')
                raw_triggers.append(
                    callable_name + " via " + opcode_name + " stream_offset=" + stream_offset + " "
                    + "op_pos=" + op_position
                )
        if not raw_triggers:
            for g in no_hook_sequence_items(_pickle_mapping_get(analysis, 'dangerous_globals', ()))[:8]:
                global_text = _pickle_text(g)
                if global_text:
                    raw_triggers.append(global_text + ' referenced by pickle GLOBAL/STACK_GLOBAL')
        return raw_triggers, record_trigger_windows(analysis)
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        try:
            record_suppressed_failure('suppressed_exception', exc, domain='runtime')
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as reporting_exc:
            _ = reporting_exc
    return [], []


__all__ = ('pickle_trigger_summaries', 'record_trigger_windows')
