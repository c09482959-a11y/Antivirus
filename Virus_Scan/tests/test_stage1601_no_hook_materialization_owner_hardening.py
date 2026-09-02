"""Stage 1601 canonical no-hook materialization owner hardening tests."""
from __future__ import annotations

from types import MappingProxyType
import json

from Virus_Scan.contracts.no_hook_materialization import (
    exact_finite_float_or_none,
    exact_text_or_none,
    materialize_json_no_hook,
    materialize_mapping_no_hook,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_materialize as model_no_hook_materialize


class HostileDictSubclass(dict):
    items_calls = 0
    keys_calls = 0
    values_calls = 0
    iter_calls = 0

    def items(self):  # pragma: no cover - test fails if invoked
        type(self).items_calls += 1
        raise RuntimeError("items hook called")

    def keys(self):  # pragma: no cover - test fails if invoked
        type(self).keys_calls += 1
        raise RuntimeError("keys hook called")

    def values(self):  # pragma: no cover - test fails if invoked
        type(self).values_calls += 1
        raise RuntimeError("values hook called")

    def __iter__(self):  # pragma: no cover - test fails if invoked
        type(self).iter_calls += 1
        raise RuntimeError("iter hook called")


class HostileStrSubclass(str):
    str_calls = 0
    repr_calls = 0
    strip_calls = 0

    def __new__(cls):
        return str.__new__(cls, "12.5")

    def __str__(self):  # pragma: no cover - test fails if invoked
        type(self).str_calls += 1
        raise RuntimeError("str hook called")

    def __repr__(self):  # pragma: no cover - test fails if invoked
        type(self).repr_calls += 1
        raise RuntimeError("repr hook called")

    def strip(self, *args, **kwargs):  # pragma: no cover - test fails if invoked
        type(self).strip_calls += 1
        raise RuntimeError("strip hook called")


class HostileDefaultNumber:
    float_calls = 0
    int_calls = 0
    bool_calls = 0

    def __float__(self):  # pragma: no cover - test fails if invoked
        type(self).float_calls += 1
        raise RuntimeError("float hook called")

    def __int__(self):  # pragma: no cover - test fails if invoked
        type(self).int_calls += 1
        raise RuntimeError("int hook called")

    def __bool__(self):  # pragma: no cover - test fails if invoked
        type(self).bool_calls += 1
        raise RuntimeError("bool hook called")


class HostileMeta(type):
    name_calls = 0

    def __getattribute__(cls, name):  # pragma: no cover - test fails if unsafe path is used
        if name == "__name__":
            type(cls).name_calls += 1
            raise RuntimeError("metaclass name hook called")
        return super().__getattribute__(name)


class HostileMetaclassValue(metaclass=HostileMeta):
    pass


def _reset() -> None:
    HostileDictSubclass.items_calls = 0
    HostileDictSubclass.keys_calls = 0
    HostileDictSubclass.values_calls = 0
    HostileDictSubclass.iter_calls = 0
    HostileStrSubclass.str_calls = 0
    HostileStrSubclass.repr_calls = 0
    HostileStrSubclass.strip_calls = 0
    HostileDefaultNumber.float_calls = 0
    HostileDefaultNumber.int_calls = 0
    HostileDefaultNumber.bool_calls = 0
    HostileMeta.name_calls = 0


def test_mappingproxy_backed_by_dict_subclass_is_rejected_without_mapping_hooks() -> None:
    _reset()
    hostile_mapping = HostileDictSubclass({"safe": "value"})
    proxy = MappingProxyType(hostile_mapping)

    assert no_hook_mapping_items(proxy) is None
    materialized = materialize_mapping_no_hook(proxy, context="phase1_owner")

    assert materialized["unavailable_reason"] == "non_materializable_phase1_owner_mapping"
    assert materialized["value_type"] == "mappingproxy"
    assert HostileDictSubclass.items_calls == 0
    assert HostileDictSubclass.keys_calls == 0
    assert HostileDictSubclass.values_calls == 0
    assert HostileDictSubclass.iter_calls == 0
    json.dumps(materialized, sort_keys=True)


def test_str_subclass_is_detached_without_caller_owned_text_hooks() -> None:
    _reset()
    hostile_text = HostileStrSubclass()

    assert exact_text_or_none(hostile_text) is None
    assert exact_finite_float_or_none(hostile_text) is None
    assert no_hook_text(hostile_text) == ("12.5", "")
    assert no_hook_finite_float(hostile_text, default=7.0, allow_exact_text=True) == (12.5, "")
    materialized = no_hook_materialize(hostile_text, reason_prefix="phase1_owner")

    assert materialized == "12.5"
    assert HostileStrSubclass.str_calls == 0
    assert HostileStrSubclass.repr_calls == 0
    assert HostileStrSubclass.strip_calls == 0
    json.dumps(materialized, sort_keys=True)


def test_hostile_numeric_default_and_bounds_do_not_invoke_numeric_or_truthiness_hooks() -> None:
    _reset()
    hostile_default = HostileDefaultNumber()

    metric, reason = no_hook_finite_float(
        HostileDefaultNumber(),
        default=hostile_default,  # type: ignore[arg-type]
        minimum=HostileDefaultNumber(),  # type: ignore[arg-type]
        maximum=HostileDefaultNumber(),  # type: ignore[arg-type]
    )

    assert metric == 0.0
    assert reason == "unsafe_numeric_value_rejected"
    assert HostileDefaultNumber.float_calls == 0
    assert HostileDefaultNumber.int_calls == 0
    assert HostileDefaultNumber.bool_calls == 0


def test_type_name_uses_builtin_type_descriptor_not_hostile_metaclass_getattribute() -> None:
    _reset()
    value = HostileMetaclassValue()

    assert no_hook_type_name(value) == "HostileMetaclassValue"
    materialized = materialize_json_no_hook(value, context="phase1_owner")

    assert materialized["value_type"] == "HostileMetaclassValue"
    assert materialized["unavailable_reason"] == "non_materializable_phase1_owner_value"
    assert HostileMeta.name_calls == 0
    json.dumps(materialized, sort_keys=True)


def test_container_limits_emit_explicit_evidence_and_model_contract_copy_matches_owner() -> None:
    large = list(range(5))

    materialized = no_hook_materialize(large, reason_prefix="phase1_owner", max_items=3)
    model_materialized = model_no_hook_materialize({"large": large}, reason_prefix="phase1_owner", max_items=3)

    assert materialized["unavailable_reason"] == "phase1_owner_sequence_size_limit_exceeded"
    assert model_materialized["large"]["unavailable_reason"] == "phase1_owner_sequence_size_limit_exceeded"
    json.dumps({"contracts": materialized, "models": model_materialized}, sort_keys=True)
