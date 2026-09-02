"""Scanner contract freeze/materialization support owners."""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    invalid_key_evidence,
    materialize_json_no_hook,
    no_hook_json_key,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    unsupported_value_evidence,
)

ScannerContractValue = object


def scanner_contract_join(*parts: str) -> str:
    out = ""
    for part in parts:
        if type(part) is str:
            out = str.__add__(out, str.__str__(part))
    return out


def _scanner_contract_evidence(value: ScannerContractValue, *, reason: str) -> Mapping[str, ScannerContractValue]:
    """Return immutable scanner-contract evidence without caller-owned hooks."""
    return MappingProxyType(unsupported_value_evidence(value, context="scanner_contract", reason=reason))


def _freeze_materialized_scanner_value(value: ScannerContractValue) -> ScannerContractValue:
    if type(value) is dict:
        frozen: dict[str, ScannerContractValue] = {}
        for key in tuple(value):
            if type(key) is str:
                frozen[str.__str__(key)] = _freeze_materialized_scanner_value(dict.__getitem__(value, key))
        return MappingProxyType(frozen)
    if type(value) is list:
        return tuple(_freeze_materialized_scanner_value(item) for item in value)
    return value


def _materialize_and_freeze_scanner_scalar(value: ScannerContractValue, *, context: str) -> ScannerContractValue:
    return _freeze_materialized_scanner_value(materialize_json_no_hook(value, context=context))


def _freeze_scanner_mapping(
    value: ScannerContractValue,
    *,
    depth: int,
    max_depth: int,
    max_items: int,
    items: tuple[tuple[ScannerContractValue, ScannerContractValue], ...],
) -> Mapping[str, ScannerContractValue]:
    if len(items) > max_items:
        return _scanner_contract_evidence(value, reason="scanner_contract_mapping_size_limit_exceeded")
    keyed: list[tuple[str, int, ScannerContractValue, str, ScannerContractValue]] = []
    for index, (key, item) in enumerate(items):
        key_text, key_reason = no_hook_json_key(key, index, prefix="scanner_contract_key")
        keyed.append((key_text, index, item, key_reason, key))
    out: dict[str, ScannerContractValue] = {}
    for key_text, index, item, key_reason, original_key in sorted(keyed, key=lambda row: (row[0], row[1])):
        if key_text in out:
            key_text = scanner_contract_join(key_text, "#", int.__str__(index))
        if key_reason:
            out[key_text] = MappingProxyType(invalid_key_evidence(original_key, context="scanner_contract", index=index))
            continue
        out[key_text] = _freeze_scanner_contract_value(item, depth=depth + 1, max_depth=max_depth, max_items=max_items)
    return MappingProxyType(out)


def _freeze_scanner_sequence(
    value: ScannerContractValue,
    *,
    depth: int,
    max_depth: int,
    max_items: int,
    source: tuple[ScannerContractValue, ...],
) -> ScannerContractValue:
    if len(source) > max_items:
        return _scanner_contract_evidence(value, reason="scanner_contract_sequence_size_limit_exceeded")
    return tuple(_freeze_scanner_contract_value(item, depth=depth + 1, max_depth=max_depth, max_items=max_items) for item in source)


def _freeze_scanner_set(
    value: ScannerContractValue,
    *,
    depth: int,
    max_depth: int,
    max_items: int,
    source: tuple[ScannerContractValue, ...],
) -> ScannerContractValue:
    if len(source) > max_items:
        return _scanner_contract_evidence(value, reason="scanner_contract_set_size_limit_exceeded")
    frozen_items = tuple(
        _freeze_scanner_contract_value(item, depth=depth + 1, max_depth=max_depth, max_items=max_items)
        for item in source
    )
    return tuple(sorted(frozen_items, key=no_hook_json_sort_key))


def _freeze_scanner_contract_value(
    value: ScannerContractValue,
    *,
    depth: int,
    max_depth: int,
    max_items: int,
) -> ScannerContractValue:
    if depth > max_depth:
        return _scanner_contract_evidence(value, reason="scanner_contract_depth_limit_exceeded")
    if value is None or type(value) in (bool, int, float):
        return _materialize_and_freeze_scanner_scalar(value, context="scanner_contract_scalar")
    if isinstance(value, str):
        return str.__str__(value)
    if type(value) is bytes or type(value) is bytearray:
        return _materialize_and_freeze_scanner_scalar(value, context="scanner_contract_bytes")
    items = no_hook_mapping_items(value)
    if items is not None:
        return _freeze_scanner_mapping(value, depth=depth, max_depth=max_depth, max_items=max_items, items=items)
    if isinstance(value, Mapping):
        return _scanner_contract_evidence(value, reason="unsupported_scanner_contract_mapping")
    if type(value) is list or type(value) is tuple:
        return _freeze_scanner_sequence(value, depth=depth, max_depth=max_depth, max_items=max_items, source=tuple(value))
    if type(value) is set or type(value) is frozenset:
        return _freeze_scanner_set(value, depth=depth, max_depth=max_depth, max_items=max_items, source=tuple(value))
    return _scanner_contract_evidence(value, reason="unsupported_scanner_contract_value")


def freeze_scanner_contract_value(value: ScannerContractValue) -> ScannerContractValue:
    """Recursively freeze scanner contract payloads at ownership boundaries."""
    return _freeze_scanner_contract_value(value, depth=0, max_depth=12, max_items=512)


def materialize_scanner_contract_value(value: ScannerContractValue) -> ScannerContractValue:
    """Return plain JSON-safe containers only at serialization/publication edges."""
    return materialize_json_no_hook(value, context="scanner_contract_materialize")


def _freeze_scanner_evidence_records(records: ScannerContractValue) -> tuple[Mapping[str, ScannerContractValue], ...]:
    if records is None:
        return ()
    if type(records) is not tuple and type(records) is not list:
        evidence = freeze_scanner_contract_value(records)
        if isinstance(evidence, Mapping):
            return (evidence,)
        return (_scanner_contract_evidence(records, reason="unsupported_scanner_evidence_records"),)
    frozen_records: list[Mapping[str, ScannerContractValue]] = []
    for record in tuple(records):
        evidence = freeze_scanner_contract_value(record)
        if isinstance(evidence, Mapping):
            frozen_records.append(evidence)
        else:
            frozen_records.append(_scanner_contract_evidence(record, reason="unsupported_scanner_evidence_records"))
    return tuple(frozen_records)


def freeze_scanner_evidence_records(records: ScannerContractValue) -> tuple[Mapping[str, ScannerContractValue], ...]:
    """Freeze scanner evidence records without retaining caller-owned dicts."""
    return _freeze_scanner_evidence_records(records)


def materialize_scanner_evidence_records(records: ScannerContractValue) -> list[dict[str, ScannerContractValue]]:
    """Materialize frozen scanner evidence for existing result metadata schemas."""
    materialized = materialize_scanner_contract_value(tuple(_freeze_scanner_evidence_records(records)))
    if type(materialized) is not list:
        return []
    out: list[dict[str, ScannerContractValue]] = []
    for item in materialized:
        if type(item) is dict:
            out.append(dict(item))
    return out


__all__ = (
    "freeze_scanner_contract_value",
    "freeze_scanner_evidence_records",
    "materialize_scanner_contract_value",
    "materialize_scanner_evidence_records",
)
