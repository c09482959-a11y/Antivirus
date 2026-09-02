from __future__ import annotations

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_text, no_hook_type_name


def _graph_exact_text(value: object) -> object:
    """Detach exact text without invoking caller-owned string hooks."""
    text, reason = no_hook_text(
        value,
        missing_reason='unsupported_graph_text_type',
        unsupported_reason='unsupported_graph_text_type',
    )
    if reason == '':
        return text
    raise TypeError(reason)


def _unsupported_graph_text(value: object) -> object:
    return 'unsupported_graph_text_type:' + no_hook_type_name(value)


def graph_exception_message(prefix: object, exc: object) -> object:
    return prefix + no_hook_type_name(exc)


def safe_graph_text(value: object) -> object:
    try:
        return _graph_exact_text(value)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _unsupported_graph_text(value)


def graph_reasoned_text(value: object, reason: object) -> object:
    try:
        text = str.strip(_graph_exact_text(value))
    except RECOVERABLE_RUNTIME_ERRORS:
        return _unsupported_graph_text(value), reason
    return text, ''


def safe_graph_text_with_reason(value: object, reason: object) -> object:
    return graph_reasoned_text(value, reason)


def graph_sequence_result(value: object, reason: object) -> object:
    if value is None:
        return (), ''
    if type(value) in (str, bytes, bytearray):
        return (value,), ''
    if type(value) is tuple:
        items = value
    elif type(value) is list:
        items = tuple(value)
    elif type(value) in (set, frozenset):
        items = tuple(sorted(value, key=safe_graph_text))
    else:
        return (), reason
    out = []
    unavailable = ''
    for item in items:
        text, item_reason = graph_reasoned_text(item, reason)
        if item_reason and not unavailable:
            unavailable = item_reason
        out.append(text)
    return tuple(out), unavailable


def safe_graph_sequence(value: object, reason: object) -> object:
    return graph_sequence_result(value, reason)


def graph_first_reason_text(value: object) -> object:
    try:
        return str.strip(_graph_exact_text(value))
    except RECOVERABLE_RUNTIME_ERRORS:
        return str.strip(_unsupported_graph_text(value))


__all__ = (
    'graph_exception_message',
    'graph_first_reason_text',
    'graph_reasoned_text',
    'graph_sequence_result',
    'safe_graph_sequence',
    'safe_graph_text',
    'safe_graph_text_with_reason',
)
