"""Binary/filetype-specific scanner config validation helpers."""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.scanners.config.contracts import ScannerConfigError
from Virus_Scan.scanners.config.validation_helpers import (
    _config_failure,
    _field_reason,
    _indexed_field_reason,
    _item_get,
    _policy_get,
    _subfield_reason,
    _text_list_tuple,
    _value_text,
)

def _binary_score_value(value: object, *, config_name: str, source: str, key: str, index: int, field_name: str) -> float:
    if type(value) is int and type(value) is not bool:
        return value + 0.0
    if type(value) is float:
        return float.__float__(value)
    raise ScannerConfigError(
        _config_failure(config_name, source, _indexed_field_reason(key, index, field_name + " must be a number"))
    )

def _require_binary_chain_definitions(policy: dict[str, object], key: str, *, source: str, config_name: str) -> tuple[dict[str, object], ...]:
    value = _policy_get(policy, key)
    if type(value) is not list or not value:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be a non-empty list")))
    out: list[dict[str, object]] = []
    for index, item in enumerate(value):
        if type(item) is not dict:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, " must be an object")))
        name = _item_get(item, "name")
        required = _item_get(item, "required")
        optional = _item_get(item, "optional", [])
        score = _item_get(item, "score")
        required_tuple = _text_list_tuple(required, require_nonempty=True)
        optional_tuple = _text_list_tuple(optional, require_nonempty=False)
        if type(name) is not str or not name:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".name must be a non-empty string")))
        if required_tuple is None:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".required must be a non-empty string list")))
        if optional_tuple is None:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".optional must be a string list")))
        score_value = _binary_score_value(score, config_name=config_name, source=source, key=key, index=index, field_name=".score")
        out.append({"name": str.__str__(name), "required": required_tuple, "optional": optional_tuple, "score": score_value})
    return tuple(out)

def _require_binary_persistence_rules(policy: dict[str, object], key: str, *, source: str, config_name: str) -> tuple[dict[str, object], ...]:
    value = _policy_get(policy, key)
    if type(value) is not list or not value:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be a non-empty list")))
    out: list[dict[str, object]] = []
    for index, item in enumerate(value):
        if type(item) is not dict:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, " must be an object")))
        mode = _item_get(item, "mode")
        tags = _item_get(item, "tags")
        score = _item_get(item, "score")
        hit = _item_get(item, "hit")
        tag_tuple = _text_list_tuple(tags, require_nonempty=True)
        if type(mode) is not str or mode not in {"any", "all"}:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".mode must be any or all")))
        if tag_tuple is None:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".tags must be a non-empty string list")))
        score_value = _binary_score_value(score, config_name=config_name, source=source, key=key, index=index, field_name=".score")
        if type(hit) is not str or not hit:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".hit must be a non-empty string")))
        out.append({"mode": str.__str__(mode), "tags": tag_tuple, "score": score_value, "hit": str.__str__(hit)})
    return tuple(out)

def _require_binary_bucket_terms(policy: dict[str, object], key: str, *, source: str, config_name: str) -> object:
    value = _policy_get(policy, key)
    required = ("network", "credential", "persistence", "injection", "evasion")
    if type(value) is not dict:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be an object")))
    out = {}
    for bucket in required:
        items = _item_get(value, bucket)
        item_tuple = _text_list_tuple(items, require_nonempty=True)
        if item_tuple is None:
            raise ScannerConfigError(_config_failure(config_name, source, _subfield_reason(key, bucket, " must be a non-empty string list")))
        out[bucket] = item_tuple
    return MappingProxyType(out)

def _require_binary_ransomware_terms(policy: dict[str, object], key: str, *, source: str, config_name: str) -> object:
    value = _policy_get(policy, key)
    required = ("traversal", "write", "rename_delete", "crypto", "marker")
    if type(value) is not dict:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be an object")))
    out = {}
    for group in required:
        items = _item_get(value, group)
        item_tuple = _text_list_tuple(items, require_nonempty=True)
        if item_tuple is None:
            raise ScannerConfigError(_config_failure(config_name, source, _subfield_reason(key, group, " must be a non-empty string list")))
        out[group] = item_tuple
    return MappingProxyType(out)

def _require_native_elf_import_semantics(policy: dict[str, object], key: str, *, source: str, config_name: str) -> tuple[tuple[str, str], ...]:
    value = _policy_get(policy, key)
    if type(value) is not list or not value:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be a non-empty list")))
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if type(item) is not dict:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, " must be an object")))
        symbol = _item_get(item, "symbol")
        operation_kind = _item_get(item, "operation_kind")
        if type(symbol) is not str or not symbol:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".symbol must be a non-empty string")))
        if type(operation_kind) is not str or not operation_kind:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".operation_kind must be a non-empty string")))
        normalized = str.__str__(symbol).casefold()
        if normalized in seen:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".symbol must be unique case-insensitively")))
        seen.add(normalized)
        out.append((normalized, str.__str__(operation_kind)))
    return tuple(out)


def _require_native_elf_syscall_semantics(policy: dict[str, object], key: str, *, source: str, config_name: str) -> tuple[tuple[int, str, str], ...]:
    value = _policy_get(policy, key)
    if type(value) is not list or not value:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be a non-empty list")))
    out: list[tuple[int, str, str]] = []
    seen: set[int] = set()
    for index, item in enumerate(value):
        if type(item) is not dict:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, " must be an object")))
        number = _item_get(item, "number")
        name = _item_get(item, "name")
        operation_kind = _item_get(item, "operation_kind")
        if type(number) is not int or type(number) is bool or number < 0 or number > 0xFFFFFFFF:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".number must be a non-negative integer")))
        if type(name) is not str or not name:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".name must be a non-empty string")))
        if type(operation_kind) is not str or not operation_kind:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".operation_kind must be a non-empty string")))
        if number in seen:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, ".number must be unique")))
        seen.add(number)
        out.append((int(number), str.__str__(name), str.__str__(operation_kind)))
    return tuple(out)


def _require_hex_bytes_tuple(policy: dict[str, object], key: str, *, minimum: int, maximum: int, source: str, config_name: str) -> tuple[bytes, ...]:
    value = _policy_get(policy, key)
    if type(value) is not list:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, " must be a list")))
    if len(value) < minimum or len(value) > maximum:
        raise ScannerConfigError(_config_failure(config_name, source, _field_reason(key, str.__add__(str.__add__(" length out of range ", _value_text(minimum)), str.__add__("..", _value_text(maximum))))))
    out: list[bytes] = []
    for index, item in enumerate(value):
        if type(item) is not str or not item or len(item) % 2:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, " must be an even-length hex string")))
        try:
            raw = bytes.fromhex(item)
        except ValueError as exc:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, " must be hexadecimal"))) from exc
        if not raw:
            raise ScannerConfigError(_config_failure(config_name, source, _indexed_field_reason(key, index, " must not decode to empty bytes")))
        out.append(raw)
    return tuple(out)

__all__ = (
    "_require_binary_bucket_terms",
    "_require_binary_chain_definitions",
    "_require_binary_persistence_rules",
    "_require_binary_ransomware_terms",
    "_require_hex_bytes_tuple",
    "_require_native_elf_import_semantics",
    "_require_native_elf_syscall_semantics",
)
