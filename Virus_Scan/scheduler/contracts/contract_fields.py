"""No-hook scalar and mapping helpers for scheduler contracts."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import first_scheduler_mapping_item_value, scheduler_mapping_item_value
import math
from types import MappingProxyType
from typing import TypeVar, overload

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.contracts.bool_field_parsing import parse_scheduler_bool_field

_T = TypeVar("_T")

ContractIssue = dict[str, object]
ContractIssues = tuple[ContractIssue, ...]
ContractMappingItems = tuple[tuple[object, object], ...]
ContractSequence = tuple[object, ...]
ContractValue = object


def contract_field_issue(value: object, *, field_name: str, reason: str) -> ContractIssue:
    return {
        "scheduler_contract_field_rejected": True,
        "field_name": field_name,
        "reason": reason,
        "value_type": no_hook_type_name(value),
    }


def contract_text(value: object, *, field_name: str, default: str = "") -> tuple[str, ContractIssues]:
    text, reason = no_hook_text(
        value,
        missing_reason="",
        unsupported_reason="scheduler_contract_text_rejected",
    )
    if reason == "":
        if text == "" and value is None:
            return default, ()
        return text, ()
    return default, (contract_field_issue(value, field_name=field_name, reason=reason),)


def contract_int(value: object, *, field_name: str, default: int = 0, minimum: int | None = None) -> tuple[int, ContractIssues]:
    if value is None:
        parsed = default
    elif type(value) is int and type(value) is not bool:
        parsed = value
    elif type(value) is str:
        try:
            parsed = int(str.__str__(value).strip())
        except ValueError:
            return default, (contract_field_issue(value, field_name=field_name, reason="scheduler_contract_int_text_invalid"),)
    else:
        return default, (contract_field_issue(value, field_name=field_name, reason="scheduler_contract_int_rejected"),)
    if minimum is not None and parsed < minimum:
        parsed = minimum
    return parsed, ()


def contract_float(value: object, *, field_name: str, default: float = 0.0, minimum: float | None = None) -> tuple[float, ContractIssues]:
    if value is None:
        parsed = default
    elif type(value) is int and type(value) is not bool:
        parsed = value + 0.0
    elif type(value) is float:
        parsed = value
    elif type(value) is str:
        try:
            parsed = float(str.__str__(value).strip())
        except ValueError:
            return default, (contract_field_issue(value, field_name=field_name, reason="scheduler_contract_float_text_invalid"),)
    else:
        return default, (contract_field_issue(value, field_name=field_name, reason="scheduler_contract_float_rejected"),)
    if not math.isfinite(parsed):
        return default, (contract_field_issue(value, field_name=field_name, reason="scheduler_contract_float_non_finite"),)
    if minimum is not None and parsed < minimum:
        parsed = minimum
    return parsed, ()


def contract_bool(value: object, *, field_name: str, default: bool = False) -> tuple[bool, ContractIssues]:
    parsed = parse_scheduler_bool_field(
        value,
        text_invalid_reason="scheduler_contract_bool_text_invalid",
        rejected_reason="scheduler_contract_bool_rejected",
    )
    if parsed.accepted:
        return parsed.value, ()
    if parsed.reason == "":
        return default, ()
    return default, (contract_field_issue(value, field_name=field_name, reason=parsed.reason),)


def contract_mapping_items(value: object) -> ContractMappingItems | None:
    if type(value) is dict or type(value) is MappingProxyType:
        return no_hook_mapping_items(value)
    return None


def contract_mapping_rejected(value: object, *, field_name: str) -> ContractIssues:
    if value is None:
        return ()
    if contract_mapping_items(value) is None:
        return (contract_field_issue(value, field_name=field_name, reason="scheduler_contract_mapping_rejected"),)
    return ()


@overload
def contract_mapping_value(value: object, key: str) -> object | None: ...


@overload
def contract_mapping_value(value: object, key: str, *, default: _T) -> _T: ...


def contract_mapping_value(value: object, key: str, *, default: object = None) -> object:
    return scheduler_mapping_item_value(contract_mapping_items(value), key, default)


@overload
def first_contract_mapping_value(value: object, *keys: str) -> object | None: ...


@overload
def first_contract_mapping_value(value: object, *keys: str, default: _T) -> _T: ...


def first_contract_mapping_value(value: object, *keys: str, default: object = None) -> object:
    return first_scheduler_mapping_item_value(contract_mapping_items(value), keys, default)


def contract_sequence(value: object, *, field_name: str) -> tuple[ContractSequence, ContractIssues]:
    if value is None:
        return (), ()
    if type(value) is list:
        return tuple(value), ()
    if type(value) is tuple:
        return tuple(value), ()
    return (), (contract_field_issue(value, field_name=field_name, reason="scheduler_contract_sequence_rejected"),)


def merge_contract_issues(*groups: object) -> tuple[object, ...]:
    merged: list[object] = []
    for group in groups:
        if not group:
            continue
        if type(group) is list:
            merged.extend(group)
        elif type(group) is tuple:
            merged.extend(group)
        else:
            merged.append(group)
    return tuple(merged)


__all__ = (
    "ContractIssue",
    "ContractIssues",
    "ContractMappingItems",
    "ContractSequence",
    "ContractValue",
    "contract_bool",
    "contract_field_issue",
    "contract_float",
    "contract_int",
    "contract_mapping_items",
    "contract_mapping_rejected",
    "contract_mapping_value",
    "contract_sequence",
    "contract_text",
    "first_contract_mapping_value",
    "merge_contract_issues",
)
