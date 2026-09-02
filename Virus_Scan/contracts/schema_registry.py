"""Immutable canonical schema ownership table."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping, NoReturn

from Virus_Scan.contracts.no_hook_materialization import no_hook_text


_SCHEMA_REGISTRATION_DRIFT = "schema registration drift"


def _raise_schema_registration_drift() -> NoReturn:
    raise RuntimeError(_SCHEMA_REGISTRATION_DRIFT)


@dataclass(frozen=True)
class SchemaDefinition:
    name: str
    owner: str
    version: int
    validator: Callable[[object], bool] | None = None


def _safe_schema_text(value: object, default: str = "") -> str:
    text, reason = no_hook_text(value, missing_reason="missing_schema_text", unsupported_reason="unsafe_schema_text_rejected")
    if reason:
        return default
    return text


def _safe_schema_version(value: object, default: int = 0) -> int:
    if type(value) is bool:
        return int(default)
    if type(value) is int:
        return value
    text, reason = no_hook_text(value, unsupported_reason="unsafe_schema_version_rejected")
    if reason:
        return int(default)
    try:
        return int(str.__str__(text).strip())
    except (TypeError, ValueError, OverflowError):
        return int(default)


def _schema(name: str, owner: str, version: int, validator: Callable[[object], bool] | None = None) -> SchemaDefinition:
    return SchemaDefinition(_safe_schema_text(name), _safe_schema_text(owner), _safe_schema_version(version), validator)


_SCHEMA_DEFINITIONS: Mapping[str, SchemaDefinition] = MappingProxyType({
    "result_record": _schema("result_record", "contracts.result_record", 1),
    "work_stage": _schema("work_stage", "contracts.work_stage", 1),
    "fact_event": _schema("fact_event", "contracts.event_facts", 1),
    "control_event": _schema("control_event", "contracts.event_facts", 1),
})


def register_schema(name: str, *, owner: str, version: int, validator: Callable[[object], bool] | None = None) -> SchemaDefinition:
    """Validate a statically owned schema declaration without mutating runtime state."""
    key = _safe_schema_text(name)
    definition = _SCHEMA_DEFINITIONS.get(key)
    if definition is None:
        exception_message = "unregistered static schema contract"
        raise KeyError(exception_message)
    owner_text = _safe_schema_text(owner)
    version_int = _safe_schema_version(version)
    if definition.owner != owner_text or definition.version != version_int:
        _raise_schema_registration_drift()
    if validator is not None and definition.validator is not validator:
        exception_message = "schema validator drift"
        raise RuntimeError(exception_message)
    return definition


def get_schema(name: str) -> SchemaDefinition | None:
    return _SCHEMA_DEFINITIONS.get(_safe_schema_text(name))


def schema_snapshot() -> dict[str, dict[str, object]]:
    rows = tuple(_SCHEMA_DEFINITIONS.items())
    return {
        key: {"owner": value.owner, "version": value.version}
        for key, value in sorted(rows)
    }


__all__ = ("SchemaDefinition", "get_schema", "register_schema", "schema_snapshot")
