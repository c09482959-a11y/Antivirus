from __future__ import annotations


import math

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.model_state import runtime_transition_counter_snapshot
from Virus_Scan.models.markov.text_boundary import markov_text
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items


def markov_reason_text(value: object, *, default_text: str = '') -> str:
    try:
        return markov_text(value, default_text=default_text)
    except RECOVERABLE_RUNTIME_ERRORS:
        return default_text


def markov_first_reason(*values: object, default_text: str = '') -> str:
    for value in values:
        text = markov_reason_text(value, default_text='')
        if text != '':
            return text
    return markov_reason_text(default_text, default_text='')


def markov_count_value(value: object) -> tuple[int | None, str]:
    """Return a validated non-negative integer Markov count without caller hooks."""
    if value is None:
        return 0, ''
    if type(value) is str and value == '':
        return 0, ''
    if type(value) is bool:
        return None, 'non_numeric_markov_count'
    if type(value) is int:
        metric = value + 0.0
    elif type(value) is float:
        metric = value
    elif type(value) is str:
        try:
            metric = float(str.__str__(value).strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return None, 'non_numeric_markov_count'
    else:
        return None, 'non_numeric_markov_count'
    if not math.isfinite(metric):
        return None, 'non_finite_markov_count'
    if metric < 0.0:
        return None, 'negative_markov_count'
    if not metric.is_integer():
        return None, 'non_integer_markov_count'
    return int(metric), ''


def counter_support(counter: object) -> tuple[int, int, str]:
    items = no_hook_mapping_items(counter)
    if items is None:
        if counter is None:
            return 0, 0, ''
        if _type_defines_callable(counter, 'items'):
            return 0, 0, 'unreadable_markov_transition_counter'
        return 0, 0, 'non_mapping_markov_transition_counter'
    return _counter_support_from_items(items)


def _counter_support_from_items(items: tuple[tuple[object, object], ...]) -> tuple[int, int, str]:
    support = 0
    vocab = 0
    first_error = ''
    for raw_key, raw_value in items:
        try:
            target_text = markov_reason_text(raw_key, default_text='')
        except RECOVERABLE_RUNTIME_ERRORS:
            target_text = ''
        if target_text == '':
            if first_error == '':
                first_error = 'invalid_markov_target'
            continue
        count, error = markov_count_value(raw_value)
        if error != '':
            if first_error == '':
                first_error = markov_reason_text(error, default_text='invalid_markov_count')
            continue
        if count is None:
            if first_error == '':
                first_error = 'invalid_markov_count'
            continue
        if count <= 0:
            continue
        support += count
        vocab += 1
    return support, vocab, first_error


def counter_target_count(counter: object, target: str) -> tuple[int, str]:
    items = no_hook_mapping_items(counter)
    if items is None:
        if counter is None:
            return 0, ''
        if _type_defines_callable(counter, 'get'):
            return 0, 'unreadable_markov_target_count'
        if _type_defines_callable(counter, 'items'):
            return 0, 'unreadable_markov_transition_counter'
        return 0, 'non_mapping_markov_transition_counter'
    target_text = markov_reason_text(target, default_text='')
    raw_count: object = 0
    for raw_key, item in items:
        if markov_reason_text(raw_key, default_text='') == target_text:
            raw_count = item
            break
    count, error = markov_count_value(raw_count)
    if error != '' or count is None:
        return 0, markov_first_reason(error, default_text='invalid_markov_target_count')
    return count, ''




def _type_defines_callable(value: object, name: str) -> bool:
    if type(name) is not str:
        return False
    class_dict = type.__getattribute__(type(value), "__dict__")
    candidate = class_dict.get(name)
    return callable(candidate)


def _markov_counter_key_matches(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) in {str, bytes, int, float, bool, type(None)}:
        return left == right
    if type(left) is tuple:
        if len(left) != len(right):
            return False
        return all(_markov_counter_key_matches(a, b) for a, b in zip(left, right, strict=False))
    if type(left) is frozenset:
        if not all(type(item) in {str, bytes, int, float, bool, type(None)} for item in left):
            return False
        if not all(type(item) in {str, bytes, int, float, bool, type(None)} for item in right):
            return False
        return left == right
    return False

def _runtime_transition_counter(key: object) -> tuple[object, str]:
    try:
        value = runtime_transition_counter_snapshot(key)
    except RECOVERABLE_RUNTIME_ERRORS:
        return {}, 'runtime_markov_transition_counter_unavailable'
    return _transition_counter_value(value)


def _transition_counter_value(value: object) -> tuple[object, str]:
    if value is None:
        return {}, ''
    if type(value) is str and value == '':
        return {}, ''
    items = no_hook_mapping_items(value)
    if items is None:
        if _type_defines_callable(value, 'items'):
            return {}, 'unreadable_markov_transition_counter'
        return {}, 'non_mapping_markov_transition_counter'
    return dict(items), ''


def snapshot_transition_counter(snapshot: object, key: object) -> tuple[object, str]:
    if snapshot is None:
        return _runtime_transition_counter(key)
    items = no_hook_mapping_items(snapshot)
    if items is None:
        if _type_defines_callable(snapshot, 'get'):
            return {}, 'unreadable_markov_snapshot'
        return {}, 'non_mapping_markov_snapshot'
    value: object = {}
    for raw_key, item in items:
        if _markov_counter_key_matches(raw_key, key):
            value = item
            break
    return _transition_counter_value(value)


__all__ = (
    'counter_support',
    'counter_target_count',
    'markov_count_value',
    'markov_first_reason',
    'markov_reason_text',
    'snapshot_transition_counter',
)
