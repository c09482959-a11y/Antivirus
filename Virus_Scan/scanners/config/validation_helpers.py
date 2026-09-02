"""Shared scanner configuration validation primitives."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scanners.config.immutable_policy import freeze_policy_contract_value
from Virus_Scan.scanners.config.immutable_policy import policy_text

from Virus_Scan.scanners.contracts import scanner_failure_evidence_record
from Virus_Scan.scanners.config.contracts import ScannerConfigError, ScannerConfigFailure

ScannerConfigValue = object
ScannerConfigPolicy = dict[str, ScannerConfigValue]

@dataclass(frozen=True, slots=True)
class _IntRequirement:
    policy: ScannerConfigPolicy
    key: str
    bounds: tuple[int, int]
    source: str
    config_name: str

@dataclass(frozen=True, slots=True)
class _StringTupleRequirement:
    policy: ScannerConfigPolicy
    key: str
    bounds: tuple[int, int]
    source: str
    config_name: str

@dataclass(frozen=True, slots=True)
class _FloatRequirement:
    policy: ScannerConfigPolicy
    key: str
    bounds: tuple[float, float]
    source: str
    config_name: str

def _value_text(value: ScannerConfigValue) -> str:
    if type(value) is str:
        return str.__str__(value)
    if type(value) is bool:
        return "True" if value else "False"
    if type(value) is int:
        return int.__str__(value)
    if type(value) is float:
        return float.__str__(value)
    return no_hook_type_name(value)

def _field_text(key: ScannerConfigValue) -> str:
    if type(key) is str and key:
        return str.__str__(key)
    return str.__add__("unsupported_scanner_config_key:", no_hook_type_name(key))

def _field_reason(key: ScannerConfigValue, suffix: str) -> str:
    return str.__add__(_field_text(key), str.__str__(suffix) if type(suffix) is str else "")

def _indexed_field_reason(key: ScannerConfigValue, index: ScannerConfigValue, suffix: str) -> str:
    index_text = int.__str__(index) if type(index) is int and type(index) is not bool else no_hook_type_name(index)
    return str.__add__(str.__add__(str.__add__(_field_text(key), "["), str.__add__(index_text, "]")), str.__str__(suffix) if type(suffix) is str else "")

def _subfield_reason(key: ScannerConfigValue, subfield: ScannerConfigValue, suffix: str) -> str:
    return str.__add__(str.__add__(str.__add__(_field_text(key), "."), _field_text(subfield)), str.__str__(suffix) if type(suffix) is str else "")

def _range_reason(key: ScannerConfigValue, minimum: ScannerConfigValue, maximum: ScannerConfigValue) -> str:
    return str.__add__(
        str.__add__(_field_text(key), " out of range "),
        str.__add__(str.__add__(_value_text(minimum), ".."), _value_text(maximum)),
    )

def _policy_get(policy: ScannerConfigValue, key: ScannerConfigValue, default: ScannerConfigValue = None) -> ScannerConfigValue:
    if type(policy) is not dict:
        return default
    return dict.get(policy, key, default)

def _item_get(item: ScannerConfigValue, key: str, default: ScannerConfigValue = None) -> ScannerConfigValue:
    if type(item) is not dict:
        return default
    return dict.get(item, key, default)

def _text_list_tuple(value: ScannerConfigValue, *, require_nonempty: bool) -> tuple[str, ...] | None:
    if type(value) is not list:
        return None
    if require_nonempty and len(value) == 0:
        return None
    out: list[str] = []
    for item in value:
        if type(item) is not str or not item:
            return None
        out.append(str.__str__(item))
    return tuple(out)

def _config_failure(config_name: str, source: str, reason: str) -> ScannerConfigFailure:
    config_text = policy_text(config_name, default="scanner_config")
    source_text = policy_text(source)
    reason_text = policy_text(reason)
    evidence = scanner_failure_evidence_record(
        "scanner_config",
        config_text,
        reason_text,
        state="failure",
        error_category="scanner_config_validation_failure",
        error_source=str.__add__("scanner_config.", config_text),
        policy_config_source=source_text,
    )
    return ScannerConfigFailure(config_text, source_text, reason_text, (evidence,))

def _require_int(requirement: _IntRequirement) -> int:
    minimum, maximum = requirement.bounds
    value = _policy_get(requirement.policy, requirement.key)
    if type(value) is not int or type(value) is bool:
        raise ScannerConfigError(
            _config_failure(requirement.config_name, requirement.source, _field_reason(requirement.key, " must be an integer"))
        )
    if value < minimum or value > maximum:
        raise ScannerConfigError(
            _config_failure(requirement.config_name, requirement.source, _range_reason(requirement.key, minimum, maximum))
        )
    return value


def _require_bool(policy: ScannerConfigPolicy, key: str, *, source: str, config_name: str) -> bool:
    value = _policy_get(policy, key)
    if type(value) is not bool:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be a boolean")))
    return value

def _require_float(requirement: _FloatRequirement) -> float:
    minimum, maximum = requirement.bounds
    value = _policy_get(requirement.policy, requirement.key)
    if type(value) is int and type(value) is not bool:
        number = value + 0.0
    elif type(value) is float:
        number = float.__float__(value)
    else:
        raise ScannerConfigError(
            _config_failure(
                requirement.config_name,
                requirement.source,
                _field_reason(requirement.key, " must be a number"),
            )
        )
    if number < minimum or number > maximum:
        raise ScannerConfigError(
            _config_failure(
                requirement.config_name,
                requirement.source,
                _range_reason(requirement.key, minimum, maximum),
            )
        )
    return number

def _require_str_tuple(requirement: _StringTupleRequirement) -> tuple[str, ...]:
    minimum, maximum = requirement.bounds
    value = _policy_get(requirement.policy, requirement.key)
    if type(value) is not list:
        raise ScannerConfigError(
            _config_failure(requirement.config_name, requirement.source, _field_reason(requirement.key, " must be a list"))
        )
    if len(value) < minimum or len(value) > maximum:
        suffix = str.__add__(str.__add__(" length out of range ", _value_text(minimum)), str.__add__("..", _value_text(maximum)))
        raise ScannerConfigError(
            _config_failure(requirement.config_name, requirement.source, _field_reason(requirement.key, suffix))
        )
    out: list[str] = []
    for index, item in enumerate(value):
        if type(item) is not str or item == "":
            raise ScannerConfigError(
                _config_failure(
                    requirement.config_name,
                    requirement.source,
                    _indexed_field_reason(requirement.key, index, " must be a non-empty string"),
                )
            )
        out.append(str.__str__(item))
    return tuple(out)


def _require_pair_tuple(policy: ScannerConfigPolicy, key: str, *, source: str, config_name: str) -> tuple[tuple[str, str], ...]:
    value = _policy_get(policy, key)
    if type(value) is not list or not value:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be a non-empty list")))
    out: list[tuple[str, str]] = []
    for index, item in enumerate(value):
        if type(item) is not dict:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, " must be an object")))
        needle = _item_get(item, "needle")
        tag = _item_get(item, "tag")
        if type(needle) is not str or not needle:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".needle must be a non-empty string")))
        if type(tag) is not str or not tag:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".tag must be a non-empty string")))
        out.append((str.__str__(needle), str.__str__(tag)))
    return tuple(out)

def _require_group_keywords(policy: ScannerConfigPolicy, key: str, *, source: str, config_name: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    value = _policy_get(policy, key)
    if type(value) is not list or not value:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be a non-empty list")))
    out: list[tuple[str, tuple[str, ...]]] = []
    for index, item in enumerate(value):
        if type(item) is not dict:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, " must be an object")))
        group = _item_get(item, "group")
        keywords = _item_get(item, "keywords")
        if type(group) is not str or not group:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".group must be a non-empty string")))
        kw_tuple = _text_list_tuple(keywords, require_nonempty=True)
        if kw_tuple is None:
            if type(keywords) is list:
                raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".keywords must be strings")))
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".keywords must be a non-empty list")))
        out.append((str.__str__(group), kw_tuple))
    return tuple(out)

def _require_weight_tuple(policy: ScannerConfigPolicy, key: str, *, source: str, config_name: str) -> tuple[tuple[str, float], ...]:
    value = _policy_get(policy, key)
    if type(value) is not list or not value:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be a non-empty list")))
    out: list[tuple[str, float]] = []
    for index, item in enumerate(value):
        if type(item) is not dict:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, " must be an object")))
        tag = _item_get(item, "tag")
        weight = _item_get(item, "weight")
        if type(tag) is not str or not tag:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".tag must be a non-empty string")))
        if type(weight) is int and type(weight) is not bool:
            weight_number = weight + 0.0
        elif type(weight) is float:
            weight_number = float.__float__(weight)
        else:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".weight must be a number")))
        out.append((str.__str__(tag), weight_number))
    return tuple(out)

def _require_named_pattern_tuple(policy: ScannerConfigPolicy, key: str, *, source: str, config_name: str) -> tuple[tuple[str, str], ...]:
    value = _policy_get(policy, key)
    if type(value) is not list or not value:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be a non-empty list")))
    out: list[tuple[str, str]] = []
    for index, item in enumerate(value):
        if type(item) is not dict:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, " must be an object")))
        name = _item_get(item, "name")
        pattern = _item_get(item, "pattern")
        if type(name) is not str or not name:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".name must be a non-empty string")))
        if type(pattern) is not str or not pattern:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".pattern must be a non-empty string")))
        out.append((str.__str__(name), str.__str__(pattern)))
    return tuple(out)

def _freeze_policy_value(value: ScannerConfigValue) -> ScannerConfigValue:
    return freeze_policy_contract_value(value)

def _require_policy_mapping(policy: ScannerConfigPolicy, key: str, *, source: str, config_name: str) -> ScannerConfigValue:
    value = _policy_get(policy, key)
    if type(value) is not dict or not value:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be a non-empty object")))
    return _freeze_policy_value(value)

__all__ = (
    "_config_failure",
    "_field_reason",
    "_freeze_policy_value",
    "_indexed_field_reason",
    "_item_get",
    "_policy_get",
    "_require_bool",
    "_require_float",
    "_require_group_keywords",
    "_require_int",
    "_require_named_pattern_tuple",
    "_require_pair_tuple",
    "_require_policy_mapping",
    "_require_str_tuple",
    "_require_weight_tuple",
    "_subfield_reason",
    "_text_list_tuple",
    "_value_text",
)
