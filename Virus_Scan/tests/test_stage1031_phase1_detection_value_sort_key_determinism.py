from types import MappingProxyType

from Virus_Scan.detection.models.stage_value_utils import (
    _detection_value_sort_key,
    freeze_detection_value,
    thaw_detection_value,
)


def test_detection_value_sort_key_sorts_nested_mapping_items_before_serializing_key() -> None:
    left = {"z": {"b": 2, "a": 1}, "a": ("one", "two")}
    right = {"a": ("one", "two"), "z": {"a": 1, "b": 2}}

    assert _detection_value_sort_key(left) == _detection_value_sort_key(right)


def test_detection_freeze_keeps_mappingproxy_order_canonical_without_retaining_state() -> None:
    nested = {"z": {"two", "one"}, "a": {"b": 2, "a": 1}}
    frozen = freeze_detection_value(MappingProxyType(nested))
    nested["z"].add("late")
    nested["a"]["late"] = 3

    assert tuple(frozen.keys()) == ("a", "z")
    assert tuple(frozen["a"].keys()) == ("a", "b")
    assert frozen["z"] == ("one", "two")
    assert thaw_detection_value(frozen) == {"a": {"a": 1, "b": 2}, "z": ["one", "two"]}
