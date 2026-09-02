"""No-hook scalar validation for queue claim jobs."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name



def claim_text(
    value: object, *, field: str, report: Callable[..., object]
) -> tuple[str, str]:
    field_name = str.__str__(field) if type(field) is str and field else "field"
    text, reason = no_hook_text(
        value,
        missing_reason="queue_claim_" + field_name + "_missing",
        unsupported_reason="queue_claim_" + field_name + "_rejected",
    )
    if reason and value is not None:
        report(
            "queue_claim_" + field_name + "_materialization_failed",
            ValueError(reason),
            fatal=True,
            extra={
                "field": field_name,
                "reason": reason,
                "value_type": no_hook_type_name(value),
            },
        )
    return text, reason


def claim_sequence(
    value: object, *, field: str, report: Callable[..., object]
) -> tuple[object, str]:
    field_name = str.__str__(field) if type(field) is str and field else "field"
    if value is None:
        return None, "queue_claim_" + field_name + "_missing"
    if type(value) in {str, int} and type(value) is not bool:
        return value, ""
    reason = "queue_claim_" + field_name + "_rejected"
    report(
        "queue_claim_" + field_name + "_materialization_failed",
        ValueError(reason),
        fatal=True,
        extra={
            "field": field_name,
            "reason": reason,
            "value_type": no_hook_type_name(value),
        },
    )
    return None, reason


__all__ = ("claim_sequence", "claim_text")
