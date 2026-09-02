from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

from Virus_Scan.models.contracts.probability_record import (
    make_probability_record,
    materialize_probability_record,
)


class HostileNameMeta(type):
    touched = 0

    def __getattribute__(cls, name):  # noqa: ANN001
        if name == "__name__":
            HostileNameMeta.touched += 1
            raise RuntimeError("hostile type name")
        return super().__getattribute__(name)


class HostileKey(metaclass=HostileNameMeta):
    touched = 0

    def __str__(self):
        HostileKey.touched += 1
        raise RuntimeError("hostile str")

    def __repr__(self):
        HostileKey.touched += 1
        raise RuntimeError("hostile repr")

    def __format__(self, spec):  # noqa: ANN001
        HostileKey.touched += 1
        raise RuntimeError("hostile format")

    def __eq__(self, other):  # noqa: ANN001
        HostileKey.touched += 1
        raise RuntimeError("hostile equality")

    def __hash__(self):
        return 1767


class HostileIterable:
    touched = 0

    def __iter__(self):
        HostileIterable.touched += 1
        raise RuntimeError("hostile iteration")

    def __str__(self):
        HostileIterable.touched += 1
        raise RuntimeError("hostile str")

    def __repr__(self):
        HostileIterable.touched += 1
        raise RuntimeError("hostile repr")


class HostileMapping(Mapping):
    touched = 0

    def __iter__(self):
        HostileMapping.touched += 1
        raise RuntimeError("hostile mapping iteration")

    def __len__(self):
        HostileMapping.touched += 1
        raise RuntimeError("hostile mapping len")

    def __getitem__(self, key):  # noqa: ANN001
        HostileMapping.touched += 1
        raise RuntimeError("hostile mapping getitem")

    def keys(self):
        HostileMapping.touched += 1
        raise RuntimeError("hostile mapping keys")

    def get(self, key, default=None):  # noqa: ANN001
        HostileMapping.touched += 1
        raise RuntimeError("hostile mapping get")


class HostileDict(dict):
    touched = 0

    def __iter__(self):
        HostileDict.touched += 1
        raise RuntimeError("hostile dict iteration")

    def keys(self):
        HostileDict.touched += 1
        raise RuntimeError("hostile dict keys")

    def items(self):
        HostileDict.touched += 1
        raise RuntimeError("hostile dict items")

    def values(self):
        HostileDict.touched += 1
        raise RuntimeError("hostile dict values")

    def get(self, key, default=None):  # noqa: ANN001
        HostileDict.touched += 1
        raise RuntimeError("hostile dict get")

    def __getitem__(self, key):  # noqa: ANN001
        HostileDict.touched += 1
        raise RuntimeError("hostile dict getitem")


def _reset_hostiles() -> None:
    HostileNameMeta.touched = 0
    HostileKey.touched = 0
    HostileIterable.touched = 0
    HostileMapping.touched = 0
    HostileDict.touched = 0


def test_stage1767_probability_record_rejects_hostile_flow_without_iter_or_typename_hooks() -> None:
    _reset_hostiles()
    hostile = HostileKey()

    record = make_probability_record(
        ready=True,
        probability=0.5,
        support=1,
        count=1,
        vocab=1,
        smoothing="laplace",
        reason="trained",
        flow={hostile},
        model_version="stage1767_probability_record_v1",
    )

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["flow"] == ()
    assert record["flow_unavailable_reason"] == "non_text_flow_item"
    assert record["probability_unavailable_reason"] == "non_text_flow_item"
    assert HostileNameMeta.touched == 0
    assert HostileKey.touched == 0


def test_stage1767_probability_materializer_rejects_hostile_mapping_without_mapping_hooks() -> None:
    _reset_hostiles()

    materialized = materialize_probability_record(HostileMapping())

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["reason"] == "unreadable_probability_record"
    assert materialized["probability_unavailable_reason"] == "unreadable_probability_record"
    assert materialized["ready_unavailable_reason"] == "unreadable_probability_record"
    assert HostileMapping.touched == 0


def test_stage1767_probability_materializer_rejects_hostile_dict_subclass_without_dict_hooks() -> None:
    _reset_hostiles()
    hostile = HostileDict(
        {
            "ready": True,
            "probability": 0.9,
            "support": 2,
            "count": 2,
            "vocab": 2,
            "smoothing": "laplace",
            "reason": "trained",
            "model_version": "stage1767_probability_record_v1",
        }
    )

    materialized = materialize_probability_record(hostile)

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["probability_unavailable_reason"] == "unreadable_probability_record"
    assert HostileDict.touched == 0


def test_stage1767_probability_materializer_does_not_compare_hostile_mapping_keys() -> None:
    _reset_hostiles()

    materialized = materialize_probability_record({HostileKey(): "unsafe"})

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["reason"] == "unreadable_probability_record"
    assert materialized["probability_unavailable_reason"] == "unreadable_probability_record"
    assert HostileNameMeta.touched == 0
    assert HostileKey.touched == 0


def test_stage1767_probability_materializer_preserves_owned_mappingproxy_and_rejects_hostile_flow() -> None:
    _reset_hostiles()
    record = MappingProxyType(
        {
            "ready": True,
            "probability": 0.7,
            "support": 3,
            "count": 3,
            "vocab": 3,
            "smoothing": "laplace",
            "reason": "trained",
            "flow": HostileIterable(),
            "model_version": "stage1767_probability_record_v1",
        }
    )

    materialized = materialize_probability_record(record)

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["flow"] == ()
    assert materialized["flow_unavailable_reason"] == "unreadable_flow"
    assert materialized["probability_unavailable_reason"] == "unreadable_flow"
    assert HostileIterable.touched == 0


def test_stage1767_probability_record_source_has_no_old_hookable_materialization_patterns() -> None:
    source = read_python_file(Path("Virus_Scan/models/contracts/probability_record.py"))

    assert "type(value).__name__" not in source
    assert "record.get(key" not in source
    assert "record[key]" not in source
    assert "record.keys()" not in source
    assert "tuple(record)" not in source
    assert "tuple(value), \"\"" in source
    assert "if type(value) in (tuple, list):" in source
