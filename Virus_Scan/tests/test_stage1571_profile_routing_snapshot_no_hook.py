from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from Virus_Scan.models.api import profile_contracts
from Virus_Scan.routing import profile_model_projection


class HostileMapping(Mapping):
    touched = False

    def __iter__(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("mapping __iter__ touched")

    def __len__(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("mapping __len__ touched")

    def __getitem__(self, key):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("mapping __getitem__ touched")

    def keys(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("mapping keys touched")

    def items(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("mapping items touched")

    def values(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("mapping values touched")


class HostileKey:
    touched = False

    def __str__(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("key __str__ touched")

    def __repr__(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("key __repr__ touched")

    def __format__(self, spec):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("key __format__ touched")


class HostileDict(dict):
    touched = False

    def items(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("dict subclass items touched")

    def keys(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("dict subclass keys touched")

    def __iter__(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("dict subclass iter touched")


class HostileValue:
    touched = False

    def __str__(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("value __str__ touched")

    def __repr__(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("value __repr__ touched")

    def __iter__(self):  # pragma: no cover - must not be reached
        type(self).touched = True
        raise AssertionError("value __iter__ touched")


def _reset() -> None:
    HostileMapping.touched = False
    HostileKey.touched = False
    HostileDict.touched = False
    HostileValue.touched = False


def test_profile_public_contract_rejects_unknown_mapping_without_mapping_hooks():
    _reset()

    result = profile_contracts._immutable_profile_value(HostileMapping())

    assert result["ready"] is False
    assert result["unavailable_reason"] == "unreadable_public_mapping_items"
    assert HostileMapping.touched is False


def test_profile_public_contract_rejects_mapping_proxy_backed_by_dict_subclass_without_hooks():
    _reset()

    result = profile_contracts._immutable_profile_value(MappingProxyType(HostileDict({"engine": "renpy"})))

    assert result["ready"] is False
    assert result["unavailable_reason"] == "unreadable_public_mapping_items"
    assert HostileDict.touched is False


def test_profile_public_contract_detaches_hostile_key_and_value_without_hooks():
    _reset()

    result = profile_contracts._immutable_profile_value({HostileKey(): HostileValue()})

    synthetic_keys = tuple(result.keys())
    assert synthetic_keys == ("<unreadable_mapping_key_0>",)
    nested = result[synthetic_keys[0]]
    assert nested["ready"] is False
    assert nested["unavailable_reason"] == "unreadable_public_contract_text"
    assert HostileKey.touched is False
    assert HostileValue.touched is False


def test_routing_profile_projection_uses_no_hook_materializer_for_hostile_public_contract():
    _reset()

    result = profile_model_projection._routing_profile_copy(HostileMapping())

    assert result["unavailable_reason"] == "non_materializable_routing_profile_value"
    assert HostileMapping.touched is False
