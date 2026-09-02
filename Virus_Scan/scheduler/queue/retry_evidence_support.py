"""Canonical no-hook normalization for scheduler retry evidence."""
from __future__ import annotations



from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_text,
)
from Virus_Scan.scheduler.queue.retry_reason_support import retry_reason
from Virus_Scan.scheduler.queue.retry_recovery_decisions import (
    retry_history_decision,
    retry_optional_int_decision,
)

RETRY_RECORD_FLAGS = (
    "final_json_must_record",
    "checkpoint_must_record",
    "replay_must_reproduce",
)



def retry_evidence_int(value: object, *, field_name: str) -> int:
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        reason=retry_reason(field_name, "rejected"),
        non_finite_reason=retry_reason(field_name, "non_finite"),
    )
    if reason:
        raise ValueError(reason)
    return parsed


def retry_evidence_optional_int(
    value: object,
    *,
    field_name: str,
) -> int | None:
    return retry_optional_int_decision(value, field_name=field_name).as_optional_int()


def retry_evidence_text(value: object, *, field_name: str) -> str:
    text, reason = scheduler_text(
        value,
        unsupported_reason=retry_reason(field_name, "rejected"),
    )
    if reason or text == "":
        raise ValueError(
            reason or retry_reason(field_name, "missing")
        )
    return text


def retry_evidence_bool(value: object, *, field_name: str) -> bool:
    parsed, reason = scheduler_bool(
        value,
        reason=retry_reason(field_name, "rejected"),
    )
    if reason:
        raise ValueError(reason)
    return parsed


def normalize_retry_evidence(
    instance: object,
    *,
    expected_type: type,
    integer_fields: tuple[str, ...] = (),
    optional_integer_fields: tuple[str, ...] = (),
    text_fields: tuple[str, ...] = (),
    boolean_fields: tuple[str, ...] = RETRY_RECORD_FLAGS,
) -> None:
    if type(instance) is not expected_type:
        try:
            expected_name_value = type.__getattribute__(expected_type, "__name__")
        except (AttributeError, TypeError):
            expected_type_name = "unknown"
        else:
            expected_type_name = (
                str.__str__(expected_name_value)
                if type(expected_name_value) is str and expected_name_value
                else "unknown"
            )
        raise TypeError("scheduler retry evidence requires exact " + expected_type_name)
    for field_name in integer_fields:
        object.__setattr__(
            instance,
            field_name,
            retry_evidence_int(
                scheduler_exact_attr(instance, field_name, owner_type=type(instance)),
                field_name=field_name,
            ),
        )
    for field_name in optional_integer_fields:
        object.__setattr__(
            instance,
            field_name,
            retry_evidence_optional_int(
                scheduler_exact_attr(instance, field_name, owner_type=type(instance)),
                field_name=field_name,
            ),
        )
    for field_name in text_fields:
        object.__setattr__(
            instance,
            field_name,
            retry_evidence_text(
                scheduler_exact_attr(instance, field_name, owner_type=type(instance)),
                field_name=field_name,
            ),
        )
    for field_name in boolean_fields:
        object.__setattr__(
            instance,
            field_name,
            retry_evidence_bool(
                scheduler_exact_attr(instance, field_name, owner_type=type(instance)),
                field_name=field_name,
            ),
        )


def retry_mapping_snapshot(value: object, *, field_name: str) -> dict[str, object]:
    items = no_hook_mapping_items(value)
    if items is not None:
        return dict(items)
    return {
        "scheduler_retry_mapping_rejected": True,
        "field_name": field_name,
        "value_type": no_hook_type_name(value),
        "queue_failure": True,
        "had_degraded_stage": True,
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_reproduce": True,
    }


def retry_history_snapshot(value: object) -> tuple[object, ...]:
    return retry_history_decision(value).as_history()


__all__ = (
    "RETRY_RECORD_FLAGS",
    "normalize_retry_evidence",
    "retry_evidence_bool",
    "retry_evidence_int",
    "retry_evidence_optional_int",
    "retry_evidence_text",
    "retry_history_snapshot",
    "retry_mapping_snapshot",
)
