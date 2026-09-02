from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.publication.json_finalization.base_projection import (
    bounded_dict,
    bounded_list,
    canonical_text_list,
    contains_non_finite_float,
)
from Virus_Scan.publication.json_finalization.compact_record import compact_json_serializable_record
from Virus_Scan.publication.json_finalization.model_metric_projection import bounded_probability_mapping
from Virus_Scan.publication.json_finalization.projection_text import (
    projection_failure,
    safe_projection_sort_key,
)
from Virus_Scan.publication.json_finalization.scheduler_projection import timeout_evidence_projection


class HostileDict(dict):
    def items(self):  # pragma: no cover - failure is the test contract
        raise AssertionError("final JSON boundary must not call Mapping.items")

    def keys(self):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call Mapping.keys")

    def values(self):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call Mapping.values")

    def get(self, key, default=None):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call Mapping.get")

    def __getitem__(self, key):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call Mapping.__getitem__")

    def __iter__(self):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call Mapping.__iter__")

    def __bool__(self):  # pragma: no cover
        raise AssertionError("final JSON boundary must not truth-test mappings")


class HostileScalar:
    def __str__(self):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call __str__")

    def __repr__(self):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call __repr__")

    def __format__(self, _spec):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call __format__")

    def __float__(self):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call __float__")

    def __int__(self):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call __int__")

    def __bool__(self):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call __bool__")


class HostileIterable:
    def __iter__(self):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call unknown __iter__")

    def __len__(self):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call unknown __len__")

    def __bool__(self):  # pragma: no cover
        raise AssertionError("final JSON boundary must not call unknown __bool__")


class HostileMeta(type):
    def __getattribute__(cls, name):  # pragma: no cover
        if name in {"__name__", "__qualname__", "__module__"}:
            raise AssertionError("final JSON boundary must not call hostile metaclass type attribute")
        return super().__getattribute__(name)


class HostileTyped(metaclass=HostileMeta):
    pass


class PlainValuesWrapper:
    def __init__(self, values):
        self._values = values

    def __iter__(self):  # pragma: no cover
        raise AssertionError("_values wrappers should be read through __dict__, not __iter__")

    def __bool__(self):  # pragma: no cover
        raise AssertionError("_values wrappers should not be truth-tested")


def test_stage1573_bounded_dict_reads_hostile_dict_subclass_without_mapping_hooks() -> None:
    hostile_value = HostileScalar()
    source = HostileDict({"probability": 0.75, "nested": HostileDict({"value": hostile_value})})

    projected = bounded_dict(MappingProxyType(source))

    assert projected["probability"] == 0.75
    assert projected["nested"]["value"]["model_signal_projection_failed"] is True
    assert projected["nested"]["value"]["reason"] == "final_json_text_unavailable"


def test_stage1573_probability_and_timeout_projection_do_not_invoke_numeric_or_mapping_hooks() -> None:
    metrics = HostileDict({"good": 1, "bad": HostileScalar(), "wide": 2.5})
    timeout = HostileDict({"timeout_budget": HostileScalar(), "worker_killed": True, "extra": HostileDict({"fatal": True})})

    probabilities = bounded_probability_mapping(MappingProxyType(metrics))
    projected_timeout = timeout_evidence_projection(MappingProxyType(timeout))

    assert probabilities["good"] == 1.0
    assert probabilities["bad"]["reason"] == "non_numeric_probability"
    assert probabilities["wide"]["reason"] == "out_of_bounds_probability"
    assert projected_timeout is not None
    assert projected_timeout["worker_killed"] is True
    assert projected_timeout["timeout_budget"]["reason"] == "final_json_text_unavailable"
    assert projected_timeout["extra"]["fatal"] is True


def test_stage1573_compact_record_and_sort_fallback_use_no_hook_type_evidence() -> None:
    hostile_key = HostileScalar()
    hostile_typed = HostileTyped()
    compact = compact_json_serializable_record(MappingProxyType(HostileDict({hostile_key: hostile_typed})))
    failure = projection_failure("stage1573_probe", hostile_typed)
    sort_key = safe_projection_sort_key(hostile_typed)

    assert "_unavailable_key_0" in compact
    assert compact["_unavailable_key_0"]["value"]["model_signal_projection_failed"] is True
    assert failure["value_type"] == "HostileTyped"
    assert sort_key[0] == "<HostileTyped>"


def test_stage1573_unknown_iterables_are_not_iterated_but_plain_values_wrappers_are_preserved() -> None:
    hostile = HostileIterable()
    wrapper = PlainValuesWrapper(("beta", "alpha"))

    hostile_list = bounded_list(hostile)
    text_list = canonical_text_list(wrapper)

    assert hostile_list[0]["model_signal_projection_failed"] is True
    assert hostile_list[0]["reason"] == "final_json_list_value_unavailable"
    assert text_list == ["alpha", "beta"]


def test_stage1573_contains_non_finite_float_uses_builtin_mapping_descriptors() -> None:
    source = HostileDict({"finite": 1.0, "bad": float("inf")})

    assert contains_non_finite_float(MappingProxyType(source)) is True
