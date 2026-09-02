from __future__ import annotations

import json
from types import MappingProxyType

from Virus_Scan.publication.model_evidence_projection.safe_mapping import (
    json_value,
    safe_mapping_get,
    safe_mapping_keys,
    safe_repr,
    safe_str,
)


class HostileDict(dict):
    touched = 0

    def items(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("mappingproxy-backed dict .items must not be called")

    def keys(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("mappingproxy-backed dict .keys must not be called")

    def values(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("mappingproxy-backed dict .values must not be called")

    def get(self, key, default=None):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("mappingproxy-backed dict .get must not be called")

    def __getitem__(self, key):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("mappingproxy-backed dict __getitem__ must not be called")

    def __iter__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("mappingproxy-backed dict __iter__ must not be called")


class HostileTypeNameMeta(type):
    touched = 0

    def __getattribute__(cls, name):  # pragma: no cover - type.__getattribute__ must bypass this
        if name in {"__name__", "__qualname__", "__module__"}:
            HostileTypeNameMeta.touched += 1
            raise AssertionError("type-name metadata hook must not be called")
        return super().__getattribute__(name)


class HostileTypeName(metaclass=HostileTypeNameMeta):
    def __str__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("__str__ must not be called")

    def __repr__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("__repr__ must not be called")


class HostileKey:
    touched = 0
    __hash__ = object.__hash__

    def __str__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("key __str__ must not be called")

    def __repr__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("key __repr__ must not be called")


class HostileValue:
    touched = 0

    def __str__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("value __str__ must not be called")

    def __repr__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("value __repr__ must not be called")


def test_stage1569_mapping_proxy_backed_by_dict_subclass_uses_builtin_descriptors() -> None:
    HostileDict.touched = 0
    backing = HostileDict({"reason": "degraded", "metadata": {"kind": "safe"}})
    proxy = MappingProxyType(backing)

    keys, reason = safe_mapping_keys(proxy)
    value = safe_mapping_get(proxy, "reason")
    projected = json_value(proxy)

    assert HostileDict.touched == 0
    assert reason == ""
    assert keys == ("metadata", "reason")
    assert value == "degraded"
    assert projected == {"metadata": {"kind": "safe"}, "reason": "degraded"}
    json.dumps(projected, sort_keys=True)


def test_stage1569_publication_type_name_evidence_bypasses_hostile_metaclass_hooks() -> None:
    HostileTypeNameMeta.touched = 0
    value = HostileTypeName()

    projected = json_value({"opaque": value})
    rendered = safe_repr(value)
    text = safe_str(value)

    assert HostileTypeNameMeta.touched == 0
    assert projected["opaque"]["unavailable_reason"] == "unsupported_model_evidence_text"
    assert projected["opaque"]["value_type"] == "HostileTypeName"
    assert rendered == "<HostileTypeName repr unavailable>"
    assert text == "<HostileTypeName>"
    json.dumps(projected, sort_keys=True)


def test_stage1569_publication_hostile_key_and_value_are_evidence_without_hooks() -> None:
    HostileKey.touched = 0
    HostileValue.touched = 0
    key = HostileKey()
    value = HostileValue()

    projected = json_value({key: value})

    assert HostileKey.touched == 0
    assert HostileValue.touched == 0
    assert list(projected) == ["<HostileKey>"]
    assert projected["<HostileKey>"]["unavailable_reason"] == "unreadable_json_mapping_key"
    json.dumps(projected, sort_keys=True)
