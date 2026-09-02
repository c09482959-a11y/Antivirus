"""JSON-safe deterministic value conversion for scheduler queue persistence."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.immutable_outputs import (
    is_trusted_scheduler_materialization_value,
    materialize_scheduler_mapping,
    unsupported_scheduler_value_evidence,
)
from Virus_Scan.scheduler.runtime.queue_json_safety_materialization import (
    queue_json_float_value,
    queue_json_safe_mapping,
    queue_json_safe_sequence,
    queue_json_safe_set,
    queue_json_scalar_value,
    queue_json_unsupported_collection,
)


def make_json_safe(value: object, _key: str | None = None) -> object:
    """Convert scheduler runtime values into deterministic JSON-safe values."""
    key_text = str.__str__(_key) if type(_key) is str else ""
    field_name = key_text or "scheduler_queue_json"
    if type(value) is dict:
        return queue_json_safe_mapping(value, key_text=key_text, safe_value=make_json_safe)
    if type(value) in {list, tuple}:
        return queue_json_safe_sequence(value, key_text=key_text, safe_value=make_json_safe)
    if type(value) in {set, frozenset}:
        return queue_json_safe_set(value, key_text=key_text, safe_value=make_json_safe)
    unsupported_collection = queue_json_unsupported_collection(value, field_name=field_name)
    if unsupported_collection is not None:
        return unsupported_collection
    scalar_value = queue_json_scalar_value(value)
    if scalar_value is not None or value is None:
        return scalar_value
    if type(value) is float:
        return queue_json_float_value(value, field_name=field_name)
    if is_trusted_scheduler_materialization_value(value):
        return make_json_safe(materialize_scheduler_mapping(value), key_text or None)
    return unsupported_scheduler_value_evidence(value, field_name=field_name)
