from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from abc import ABCMeta
from collections.abc import Mapping
from pathlib import Path

from types import MappingProxyType

from Virus_Scan.models.api import adaptive_signals
from Virus_Scan.models.contracts.model_feature_bundle import (
    make_model_feature_bundle,
    materialize_model_feature_bundle,
)


class HostileTypeNameMeta(ABCMeta):
    touched = 0

    def __getattribute__(cls, name: str):  # noqa: ANN204
        if name == "__name__":
            type.__setattr__(cls, "touched", type.__getattribute__(cls, "touched") + 1)
            raise RuntimeError("type name hook should not execute")
        return type.__getattribute__(cls, name)


class HostileFeatureValue(metaclass=HostileTypeNameMeta):
    touched = 0

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("str hook should not execute")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("repr hook should not execute")

    def __format__(self, spec: str) -> str:
        type(self).touched += 1
        raise RuntimeError("format hook should not execute")


class HostileFeatureMapping(Mapping, metaclass=HostileTypeNameMeta):
    touched = 0

    def __iter__(self):  # noqa: ANN204
        type(self).touched += 1
        raise RuntimeError("iter hook should not execute")

    def __len__(self) -> int:
        type(self).touched += 1
        raise RuntimeError("len hook should not execute")

    def __getitem__(self, key):  # noqa: ANN001, ANN204
        type(self).touched += 1
        raise RuntimeError("getitem hook should not execute")

    def keys(self):  # noqa: ANN204
        type(self).touched += 1
        raise RuntimeError("keys hook should not execute")

    def get(self, key, default=None):  # noqa: ANN001, ANN204
        type(self).touched += 1
        raise RuntimeError("get hook should not execute")


def _reset_hostile_state() -> None:
    HostileTypeNameMeta.touched = 0
    HostileFeatureValue.touched = 0
    HostileFeatureMapping.touched = 0


def test_stage1764_feature_bundle_rejects_hostile_values_without_type_or_text_hooks() -> None:
    _reset_hostile_state()
    hostile = HostileFeatureValue()

    bundle = make_model_feature_bundle({"payload": hostile}, model_version="stage1764")
    materialized = materialize_model_feature_bundle(bundle)

    assert HostileTypeNameMeta.touched == 0
    assert HostileFeatureValue.touched == 0
    assert materialized["payload"] == {
        "value": None,
        "unavailable_reason": "unsupported_model_feature_value",
        "value_type": "HostileFeatureValue",
    }


def test_stage1764_feature_bundle_rejects_hostile_mapping_without_mapping_hooks() -> None:
    _reset_hostile_state()
    hostile = HostileFeatureMapping()

    bundle = make_model_feature_bundle(hostile, model_version="stage1764")
    materialized = materialize_model_feature_bundle(bundle)

    assert HostileTypeNameMeta.touched == 0
    assert HostileFeatureMapping.touched == 0
    assert bundle["values_unavailable_reason"] == "unreadable_model_feature_mapping"
    assert bundle["values_type"] == "HostileFeatureMapping"
    assert materialized["values_unavailable_reason"] == "unreadable_model_feature_mapping"
    assert materialized["values_type"] == "HostileFeatureMapping"


def test_stage1764_materialize_rejects_hostile_mapping_without_mapping_hooks() -> None:
    _reset_hostile_state()
    hostile = HostileFeatureMapping()

    materialized = materialize_model_feature_bundle(hostile)

    assert HostileTypeNameMeta.touched == 0
    assert HostileFeatureMapping.touched == 0
    assert materialized == {
        "unavailable_reason": "unreadable_model_feature_mapping",
        "value_type": "HostileFeatureMapping",
    }


def test_stage1764_feature_bundle_preserves_exact_dict_and_mappingproxy_inputs() -> None:
    source = MappingProxyType({"nested": MappingProxyType({"beta": 2, "alpha": 1})})

    bundle = make_model_feature_bundle(source, model_version="stage1764")
    materialized = materialize_model_feature_bundle(bundle)

    assert materialized["nested"] == {"alpha": 1, "beta": 2}
    assert materialized["model_version"] == "stage1764"


def test_stage1764_immutable_adaptive_signal_rejects_hostile_mapping_without_mapping_hooks() -> None:
    _reset_hostile_state()
    hostile = HostileFeatureMapping()

    frozen = adaptive_signals.immutable_adaptive_signal(hostile, model_version="stage1764")
    materialized = materialize_model_feature_bundle(frozen)

    assert HostileTypeNameMeta.touched == 0
    assert HostileFeatureMapping.touched == 0
    assert materialized["ready"] is False
    assert materialized["score"] == 0.0
    assert materialized["degraded"] is True
    assert materialized["unavailable_reason"] == "unsupported_adaptive_public_mapping"
    assert materialized["values_type"] == "HostileFeatureMapping"


def test_stage1764_model_feature_bundle_source_no_raw_type_or_mapping_traversal() -> None:
    source = read_python_file(Path("Virus_Scan/models/contracts/model_feature_bundle.py"))

    assert "type(value).__name__" not in source
    assert "type(values).__name__" not in source
    assert "type(bundle).__name__" not in source
    assert ".keys()" not in source
    assert "value.get(" not in source
    assert "value[key]" not in source
