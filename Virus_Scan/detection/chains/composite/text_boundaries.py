"""No-hook text, mapping, and diagnostic boundaries for composite chain detection."""
from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text, no_hook_type_name

_MAPPING_PROXY_TYPE: type[object] = type(MappingProxyType({}))


def composite_text(value: object, *, default_text: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_composite_chain_text",
        unsupported_reason="unsafe_composite_chain_text_rejected",
    )
    if reason:
        return str.__str__(default_text) if type(default_text) is str else ""
    return str.strip(text)


def composite_lower_text(value: object, *, default_text: str = "") -> str:
    text = composite_text(value, default_text=default_text)
    return str.lower(text)


def composite_metric_text(value: object, *, default_value: float = 0.0, precision: str = ".1f") -> str:
    metric, reason = no_hook_finite_float(
        value,
        default=default_value,
        reason="unsafe_composite_chain_metric_rejected",
        non_finite_reason="unsafe_composite_chain_metric_rejected",
    )
    if reason:
        metric = default_value
    if type(precision) is str:
        return float.__format__(metric, precision)
    return float.__str__(metric)


def composite_colon_join(*parts: str) -> str:
    out = ""
    for part in parts:
        text = str.__str__(part) if type(part) is str else composite_text(part)
        out = text if not out else str.__add__(str.__add__(out, ":"), text)
    return out


def composite_prefixed(prefix: str, value: object) -> str:
    return str.__add__(str.__str__(prefix), composite_text(value))


def composite_type_diagnostic(prefix: str, value: object) -> str:
    return str.__add__(str.__str__(prefix), no_hook_type_name(value))


def exact_mapping_items(mapping: object) -> tuple[tuple[object, object], ...]:
    if type(mapping) is dict:
        return tuple(dict.items(mapping))
    if type(mapping) is _MAPPING_PROXY_TYPE:
        proxy = cast("Mapping[Any, Any]", mapping)
        return tuple(proxy.items())
    return ()


def exact_mapping_keys(mapping: object) -> tuple[object, ...]:
    if type(mapping) is dict:
        return tuple(dict.keys(mapping))
    if type(mapping) is _MAPPING_PROXY_TYPE:
        proxy = cast("Mapping[Any, Any]", mapping)
        return tuple(proxy.keys())
    return ()


def exact_mapping_values(mapping: object) -> tuple[object, ...]:
    if type(mapping) is dict:
        return tuple(dict.values(mapping))
    if type(mapping) is _MAPPING_PROXY_TYPE:
        proxy = cast("Mapping[Any, Any]", mapping)
        return tuple(proxy.values())
    return ()


def exact_record_value(record: object, key: str, default_value: object = None) -> object:
    if type(record) is dict:
        return dict.get(record, key, default_value)
    if type(record) is _MAPPING_PROXY_TYPE:
        proxy = cast("Mapping[Any, Any]", record)
        return proxy.get(key, default_value)
    return default_value


def exact_sequence(value: object) -> tuple[object, ...]:
    value_type = type(value)
    if value_type is tuple:
        return value
    if value_type is list:
        return tuple(value)
    if value_type is set:
        return tuple(value)
    if value_type is frozenset:
        return tuple(value)
    return ()
