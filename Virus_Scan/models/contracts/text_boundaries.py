"""No-hook text and reason-key boundaries for model contract records."""
from __future__ import annotations
from typing import TYPE_CHECKING

import math
from types import MappingProxyType

from Virus_Scan.models.contracts.no_hook_materialization import no_hook_type_name

if TYPE_CHECKING:
    from collections.abc import Mapping

def model_contract_type_label(value: object) -> str:
    return str.__add__(str.__add__("<", no_hook_type_name(value)), ">")


def model_contract_safe_text(value: object) -> str:
    if isinstance(value, str):
        return "".join((str.__str__(value),))
    if type(value) is bytes:
        return bytes(value).decode("utf-8", "replace")
    if type(value) is bytearray:
        return bytes(value).decode("utf-8", "replace")
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return int.__str__(value)
    if type(value) is float and math.isfinite(value):
        return float.__str__(value)
    return model_contract_type_label(value)


def model_contract_field_reason(prefix: str, field_name: object) -> str:
    safe_prefix = str.__str__(prefix) if type(prefix) is str else "model_field"
    safe_field = str.__str__(field_name) if type(field_name) is str else "unknown_field"
    return str.__add__(str.__add__(safe_prefix, "_"), safe_field)


def model_contract_metric_reason(prefix: str, field_name: object) -> str:
    return str.__add__(model_contract_field_reason(prefix, field_name), "_metric")


def model_contract_text_field(
    value: object,
    *,
    field_name: str,
    default: str,
    invalid_prefix: str = "unreadable",
) -> tuple[str, str]:
    if isinstance(value, str):
        text = str.strip(model_contract_safe_text(value))
        if text != "":
            return text, ""
        return default, model_contract_field_reason("blank", field_name)
    return default, model_contract_field_reason(invalid_prefix, field_name)


def model_contract_unavailable_reason_key(name: object) -> str:
    safe_name = str.__str__(name) if type(name) is str else "unknown_model_field"
    return str.__add__(safe_name, "_unavailable_reason")


def model_contract_unavailable_summary_reason(name: object) -> str:
    safe_name = str.__str__(name) if type(name) is str else "unknown_model_field"
    if str.endswith(safe_name, "_unavailable_reason"):
        safe_name = str.removesuffix(safe_name, "_unavailable_reason")
    return str.__add__(safe_name, "_unavailable")


def model_contract_unavailable_record(reason: str, value: object | None = None) -> Mapping[str, object]:
    record: dict[str, object] = {"value": None, "unavailable_reason": model_contract_safe_text(reason)}
    if value is not None:
        record["value_type"] = no_hook_type_name(value)
    return MappingProxyType(record)


def model_contract_json_safe_scalar(value: object) -> bool:
    return (
        value is None
        or isinstance(value, str)
        or type(value) in (int, bool)
        or (type(value) is float and math.isfinite(value))
    )


__all__ = (
    "model_contract_field_reason",
    "model_contract_json_safe_scalar",
    "model_contract_metric_reason",
    "model_contract_safe_text",
    "model_contract_text_field",
    "model_contract_type_label",
    "model_contract_unavailable_reason_key",
    "model_contract_unavailable_record",
    "model_contract_unavailable_summary_reason",
)
