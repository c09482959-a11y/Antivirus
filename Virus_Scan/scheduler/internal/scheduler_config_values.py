"""No-hook process-queue environment value parsing."""
from __future__ import annotations



from Virus_Scan.contracts.env_config import float_env, int_env
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_text,
    no_hook_type_name,
)


def _record_rejection(record_suppressed: object, stage: str, reason: str, *, field: str, value: object) -> None:
    record_suppressed(
        stage,
        ValueError(reason),
        extra={
            "field": field,
            "name": field,
            "reason": reason,
            "value_type": no_hook_type_name(value),
        },
    )



def _config_name(name: object, *, record_suppressed: object, stage: str) -> str:
    text, reason = no_hook_text(
        name,
        missing_reason="scheduler_config_name_missing",
        unsupported_reason="scheduler_config_name_rejected",
    )
    if reason or text == "":
        _record_rejection(
            record_suppressed,
            stage,
            reason or "scheduler_config_name_blank",
            field="name",
            value=name,
        )
        return ""
    return text


def _config_float(value: object, *, default: float, record_suppressed: object, stage: str, field: str) -> float:
    field_prefix = str.__str__(field) if type(field) is str and field else "scheduler_config"
    metric, reason = no_hook_finite_float(
        value,
        default=default,
        reason=str.__add__(field_prefix, "_rejected"),
        non_finite_reason=str.__add__(field_prefix, "_non_finite"),
        allow_exact_text=True,
    )
    if reason:
        _record_rejection(record_suppressed, stage, reason, field=field, value=value)
    return metric


def _config_int(value: object, *, default: int, record_suppressed: object, stage: str, field: str) -> int:
    field_prefix = str.__str__(field) if type(field) is str and field else "scheduler_config"
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        default=default,
        reason=str.__add__(field_prefix, "_rejected"),
        non_finite_reason=str.__add__(field_prefix, "_non_finite"),
        allow_exact_text=True,
    )
    if reason:
        _record_rejection(record_suppressed, stage, reason, field=field, value=value)
    return parsed


def process_queue_env_float(
    name: str,
    default: object,
    *,
    minimum: float | None = None,
    record_suppressed: object,
    env_get: object=None,
) -> float:
    default_metric = _config_float(
        default,
        default=0.0,
        record_suppressed=record_suppressed,
        stage="process_queue_env_float_default_invalid",
        field="default",
    )
    lower = 0.0 if minimum is None else _config_float(
        minimum,
        default=0.0,
        record_suppressed=record_suppressed,
        stage="process_queue_env_float_minimum_invalid",
        field="minimum",
    )
    name_text = _config_name(
        name, record_suppressed=record_suppressed, stage="process_queue_env_float_name_invalid"
    )
    if name_text == "":
        return max(lower, default_metric)
    if env_get is None:
        return float_env(name_text, default_metric, lower, None)
    try:
        raw_value = env_get(name_text, float.__str__(default_metric))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        record_suppressed("process_queue_env_float_read_failed", exc, extra={"name": name_text})
        return max(lower, default_metric)
    value = _config_float(
        raw_value,
        default=default_metric,
        record_suppressed=record_suppressed,
        stage="process_queue_env_float_invalid",
        field=name_text,
    )
    return max(lower, value)


def process_queue_env_int(
    name: str,
    default: object,
    *,
    minimum: int | None = None,
    record_suppressed: object,
    env_get: object=None,
) -> int:
    default_value = _config_int(
        default,
        default=0,
        record_suppressed=record_suppressed,
        stage="process_queue_env_int_default_invalid",
        field="default",
    )
    lower = 0 if minimum is None else _config_int(
        minimum,
        default=0,
        record_suppressed=record_suppressed,
        stage="process_queue_env_int_minimum_invalid",
        field="minimum",
    )
    name_text = _config_name(
        name, record_suppressed=record_suppressed, stage="process_queue_env_int_name_invalid"
    )
    if name_text == "":
        return max(lower, default_value)
    if env_get is None:
        return int_env(name_text, default_value, lower, None)
    try:
        raw_value = env_get(name_text, int.__str__(default_value))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        record_suppressed("process_queue_env_int_read_failed", exc, extra={"name": name_text})
        return max(lower, default_value)
    value = _config_int(
        raw_value,
        default=default_value,
        record_suppressed=record_suppressed,
        stage="process_queue_env_int_invalid",
        field=name_text,
    )
    return max(lower, value)


__all__ = ("process_queue_env_float", "process_queue_env_int")
