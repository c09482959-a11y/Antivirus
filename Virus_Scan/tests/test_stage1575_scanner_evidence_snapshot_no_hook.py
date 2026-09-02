from __future__ import annotations

import gc
from types import MappingProxyType

from Virus_Scan.scanners.contracts.scanner_evidence import (
    freeze_scanner_contract_value,
    freeze_scanner_evidence_records,
    materialize_scanner_evidence_records,
)


class HostileValue:
    def __str__(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile __str__ invoked")

    def __repr__(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile __repr__ invoked")

    def __bool__(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile __bool__ invoked")

    def __int__(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile __int__ invoked")

    def __float__(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile __float__ invoked")

    def __iter__(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile __iter__ invoked")


class HostileMapping(dict):
    def keys(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile keys invoked")

    def items(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile items invoked")

    def values(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile values invoked")

    def get(self, *args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("hostile get invoked")

    def __iter__(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile iter invoked")

    def __getitem__(self, key):  # pragma: no cover - must never be called
        raise AssertionError("hostile getitem invoked")


class HostileKey:
    def __str__(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile key __str__ invoked")

    def __repr__(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile key __repr__ invoked")


class HostileSequence(list):
    def __iter__(self):  # pragma: no cover - must never be called
        raise AssertionError("hostile sequence iter invoked")


def _contains_identity(root, target_id: int, *, limit: int = 2048) -> bool:
    seen: set[int] = set()
    stack = [root]
    while stack and len(seen) < limit:
        item = stack.pop()
        item_id = id(item)
        if item_id == target_id:
            return True
        if item_id in seen:
            continue
        seen.add(item_id)
        try:
            stack.extend(gc.get_referents(item))
        except Exception:  # pragma: no cover - GC may reject interpreter internals
            continue
    return False


def test_stage1575_scanner_contract_freeze_rejects_hostile_mapping_without_hooks():
    hostile = HostileMapping({"x": "y"})

    frozen = freeze_scanner_contract_value(hostile)

    assert frozen["unavailable_reason"] == "unsupported_scanner_contract_mapping"
    assert frozen["context"] == "scanner_contract"
    assert not _contains_identity(frozen, id(hostile))


def test_stage1575_scanner_contract_freeze_rejects_mappingproxy_backed_by_hostile_dict():
    hostile = HostileMapping({"x": "y"})
    proxy = MappingProxyType(hostile)

    frozen = freeze_scanner_contract_value(proxy)

    assert frozen["unavailable_reason"] == "unsupported_scanner_contract_mapping"
    assert not _contains_identity(frozen, id(hostile))


def test_stage1575_scanner_contract_freeze_evidences_hostile_key_without_stringifying():
    key = HostileKey()
    payload = {key: HostileValue()}

    frozen = freeze_scanner_contract_value(payload)
    materialized = materialize_scanner_evidence_records((frozen,))

    record = materialized[0]
    assert "scanner_contract_key_0" in record
    assert record["scanner_contract_key_0"]["unavailable_reason"] == "invalid_json_mapping_key"
    assert not _contains_identity(frozen, id(key))


def test_stage1575_scanner_evidence_records_do_not_iterate_unknown_sequences():
    hostile = HostileSequence([{"scanner_name": "binary"}])

    records = freeze_scanner_evidence_records(hostile)

    assert len(records) == 1
    assert records[0]["unavailable_reason"] == "unsupported_scanner_contract_value"
    assert not _contains_identity(records, id(hostile))


def test_stage1575_scanner_contract_freeze_detaches_mutable_exact_containers():
    payload = {"scanner": {"tags": ["a"]}}

    frozen = freeze_scanner_contract_value(payload)
    payload["scanner"]["tags"].append("mutated")

    assert frozen["scanner"]["tags"] == ("a",)
    materialized = materialize_scanner_evidence_records((frozen,))
    assert materialized[0]["scanner"]["tags"] == ["a"]
