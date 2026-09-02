from __future__ import annotations


from Virus_Scan.models.contracts.no_hook_materialization import no_hook_finite_float, no_hook_mapping_items
from Virus_Scan.models.markov.counters import markov_count_value

def _markov_mapping_value(mapping: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for raw_key, raw_value in items:
        if type(raw_key) is str and raw_key == key:
            return raw_value
    return default


def _markov_mapping_is_true(mapping: object, key: str) -> bool:
    return _markov_mapping_value(mapping, key, False) is True


def _markov_mapping_float(mapping: object, key: str, default: float = 0.0) -> tuple[float, str]:
    value = _markov_mapping_value(mapping, key, None)
    if value is None:
        return default, 'missing_markov_numeric_value'
    metric, reason = no_hook_finite_float(
        value,
        default=default,
        reason='invalid_markov_numeric_value',
        non_finite_reason='invalid_markov_numeric_value',
    )
    return metric, reason


def _markov_mapping_int(mapping: object, key: str, default: int = 0) -> int:
    value = _markov_mapping_value(mapping, key, default)
    count, error = markov_count_value(value)
    if error != '' or count is None:
        return default
    return int(count)


def _markov_pair_baseline_value(mapping: object, left: str, right: str, default: object = 0) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for raw_key, raw_value in items:
        if (
            type(raw_key) is tuple
            and len(raw_key) == 2
            and type(raw_key[0]) is str
            and type(raw_key[1]) is str
            and raw_key[0] == left
            and raw_key[1] == right
        ):
            return raw_value
    return default
