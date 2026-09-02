"""No-hook reason helpers for scheduler file execution boundaries."""
from __future__ import annotations



from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text

_REASON_PREFIX = "scheduler_execution_"
_FIELD_NAME_FALLBACK = "field"
_MAPPING_REJECTED = "_mapping_rejected"
_SEQUENCE_REJECTED = "_sequence_rejected"
_TEXT_REJECTED = "_text_rejected"
_TEXT_MISSING = "_text_missing"
_BOOL_REJECTED = "_bool_rejected"
_FLOAT_REJECTED = "_float_rejected"
_PATH_REJECTED_PREFIX = "_path_rejected:"
_PATH_MISSING = "scheduler_path_missing"


def execution_boundary_reason(field_name: object, suffix: str) -> str:
    text, issue = no_hook_text(
        field_name,
        missing_reason="scheduler_execution_field_name_missing",
        unsupported_reason="scheduler_execution_field_name_rejected",
    )
    field_text = text if issue == "" and text != "" else _FIELD_NAME_FALLBACK
    return str.__add__(str.__add__(_REASON_PREFIX, field_text), suffix)


def execution_path_rejected_reason(field_name: object, reason: str) -> str:
    detail = reason if type(reason) is str and reason != "" else _PATH_MISSING
    return str.__add__(execution_boundary_reason(field_name, _PATH_REJECTED_PREFIX), detail)


def execution_float_value(
    value: object,
    *,
    default_value: float,
    minimum: float | None,
    field_name: object,
) -> tuple[float, str]:
    return no_hook_finite_float(
        value,
        default=default_value,
        minimum=minimum,
        reason=execution_boundary_reason(field_name, _FLOAT_REJECTED),
        allow_exact_text=True,
    )


__all__ = (
    "execution_boundary_reason",
    "execution_float_value",
    "execution_path_rejected_reason",
)
