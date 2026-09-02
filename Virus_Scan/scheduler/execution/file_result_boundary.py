"""No-hook scalar and container boundaries for scheduler file execution."""
from __future__ import annotations



from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
)
from Virus_Scan.scheduler.execution.file_result_boundary_support import (
    execution_boundary_reason,
    execution_float_value,
    execution_path_rejected_reason,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_path_text,
    scheduler_text,
)


def execution_mapping(value: object, *, field_name: str) -> dict[object, object]:
    items = no_hook_mapping_items(value)
    if items is None:
        raise ValueError(execution_boundary_reason(field_name, "_mapping_rejected"))
    return dict(items)


def execution_record_mapping(value: object, *, field_name: str) -> dict[str, object]:
    """Materialize a scheduler result record with exact string keys."""
    mapping = execution_mapping(value, field_name=field_name)
    record: dict[str, object] = {}
    for key, item_value in mapping.items():
        if type(key) is not str:
            raise ValueError(execution_boundary_reason(field_name, "_string_key_mapping_rejected"))
        record[str.__str__(key)] = item_value
    return record


def execution_sequence(value: object, *, field_name: str) -> tuple[object, ...]:
    if value is None:
        return ()
    if type(value) not in {tuple, list, set, frozenset}:
        raise ValueError(execution_boundary_reason(field_name, "_sequence_rejected"))
    return no_hook_sequence_items(value)


def execution_text(
    value: object,
    *,
    field_name: str,
    allow_empty: bool = True,
    default: str | None = None,
) -> str:
    if value is None and default is not None:
        return default
    text, reason = scheduler_text(
        value,
        unsupported_reason=execution_boundary_reason(field_name, "_text_rejected"),
    )
    if reason or (not allow_empty and text == ""):
        raise ValueError(reason or execution_boundary_reason(field_name, "_text_missing"))
    return text


def execution_bool(value: object, *, field_name: str, default: bool = False) -> bool:
    if value is None:
        return default
    parsed, reason = scheduler_bool(
        value,
        default=default,
        reason=execution_boundary_reason(field_name, "_bool_rejected"),
    )
    if reason:
        raise ValueError(reason)
    return parsed


def execution_float(
    value: object,
    *,
    field_name: str,
    default: float = 0.0,
    minimum: float | None = None,
) -> float:
    parsed, reason = execution_float_value(
        value,
        default_value=default,
        minimum=minimum,
        field_name=field_name,
    )
    if reason:
        raise ValueError(reason)
    return parsed


def execution_path_text(value: object, *, field_name: str) -> str:
    text, reason = scheduler_path_text(value)
    if reason or text == "":
        raise ValueError(execution_path_rejected_reason(field_name, reason))
    return text


def execution_evidence_present(value: object) -> bool:
    if value is None or value is False:
        return False
    if type(value) is bool:
        return value
    if type(value) in {int, float}:
        return value != 0
    if type(value) is str:
        return str.__len__(value) > 0
    if type(value) is tuple:
        return tuple.__len__(value) > 0
    if type(value) is list:
        return list.__len__(value) > 0
    if type(value) is set:
        return set.__len__(value) > 0
    if type(value) is frozenset:
        return frozenset.__len__(value) > 0
    if type(value) is dict:
        return dict.__len__(value) > 0
    return True


def execution_result_degraded(result: dict[object, object]) -> bool:
    return any(
        execution_evidence_present(dict.get(result, key))
        for key in ("error", "errors", "crash_traceback", "timed_out")
    )


__all__ = (
    "execution_bool",
    "execution_evidence_present",
    "execution_float",
    "execution_mapping",
    "execution_path_text",
    "execution_record_mapping",
    "execution_result_degraded",
    "execution_sequence",
    "execution_text",
)
