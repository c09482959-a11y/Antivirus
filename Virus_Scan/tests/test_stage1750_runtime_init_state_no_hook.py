from Virus_Scan.tests.support.static_inventory import read_python_file

from collections import Counter, defaultdict
from pathlib import Path
from types import MappingProxyType

from Virus_Scan.runtime.init_state import (
    InitStateOwner,
    freeze_init_value,
    get_init_value,
    publish_init_value,
    publish_init_values,
)



class HostileInitDict(dict):
    touched = 0

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not call items")


class HostileInitKey:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileInitDeepcopy:
    touched = 0

    def __deepcopy__(self, memo):
        type(self).touched += 1
        raise RuntimeError("do not deepcopy")


class HostileInitItems:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")


def test_stage1750_freeze_init_value_rejects_dict_subclass_without_items_hook():
    HostileInitDict.touched = 0

    frozen = freeze_init_value(HostileInitDict({"a": 1}))

    assert HostileInitDict.touched == 0
    assert isinstance(frozen, MappingProxyType)
    assert frozen["unavailable_reason"] == "non_materializable_init_value"
    assert frozen["value_type"] == "HostileInitDict"


def test_stage1750_freeze_init_value_rejects_hostile_mapping_key_without_string_hooks():
    HostileInitKey.touched = 0

    frozen = freeze_init_value({HostileInitKey(): "value"})

    assert HostileInitKey.touched == 0
    assert isinstance(frozen, MappingProxyType)
    evidence = frozen["init_value_key_0"]
    assert evidence["unavailable_reason"] == "invalid_key_type"
    assert evidence["value_type"] == "HostileInitKey"


def test_stage1750_freeze_init_value_rejects_unsupported_object_without_deepcopy_hook():
    HostileInitDeepcopy.touched = 0

    frozen = freeze_init_value(HostileInitDeepcopy())

    assert HostileInitDeepcopy.touched == 0
    assert isinstance(frozen, MappingProxyType)
    assert frozen["unavailable_reason"] == "non_materializable_init_value"
    assert frozen["value_type"] == "HostileInitDeepcopy"


def test_stage1750_publish_init_values_rejects_hostile_names_without_hooks():
    HostileInitKey.touched = 0

    frozen = publish_init_values(((HostileInitKey(), "value"),))

    assert HostileInitKey.touched == 0
    evidence = frozen["init_value_name_0"]
    assert evidence["unavailable_reason"] == "invalid_key_type"
    assert evidence["value_type"] == "HostileInitKey"


def test_stage1750_publish_and_get_init_value_reject_hostile_name_without_hooks():
    HostileInitKey.touched = 0

    published = publish_init_value(HostileInitKey(), "value")
    fetched = get_init_value(HostileInitKey(), "default")

    assert HostileInitKey.touched == 0
    assert published["unavailable_reason"] == "invalid_key_type"
    assert published["value_type"] == "HostileInitKey"
    assert fetched["unavailable_reason"] == "invalid_key_type"
    assert fetched["value_type"] == "HostileInitKey"


def test_stage1750_publish_init_values_rejects_unknown_iterable_without_iter_or_bool_hooks():
    HostileInitItems.touched = 0

    frozen = publish_init_values(HostileInitItems())

    assert HostileInitItems.touched == 0
    evidence = frozen["init_values_materialization"]
    assert evidence["unavailable_reason"] == "non_materializable_init_items"
    assert evidence["value_type"] == "HostileInitItems"


def test_stage1750_runtime_init_value_freeze_preserves_owned_dict_items_and_nested_immutability():
    nested = {"values": ["before"]}

    frozen = freeze_init_value(MappingProxyType({"runtime": nested}))
    nested["values"].append("after")

    assert isinstance(frozen, MappingProxyType)
    assert frozen["runtime"]["values"] == ("before",)


def test_stage1750_runtime_init_value_freeze_preserves_counter_and_defaultdict_semantics():
    counter = Counter({"b": 2, "a": 3})
    defaulted = defaultdict(list)
    defaulted["z"].append({"nested": ["x"]})

    frozen_counter = freeze_init_value(counter)
    frozen_defaulted = freeze_init_value(defaulted)

    assert dict(frozen_counter) == {"a": 3, "b": 2}
    assert frozen_defaulted["z"][0]["nested"] == ("x",)



def test_stage1971_init_state_duplicate_keys_and_dict_items_view_are_no_hook():
    HostileInitKey.touched = 0
    owner = InitStateOwner()

    frozen_duplicate_mapping = freeze_init_value({1: "int-key", "1": "text-key"})
    published_from_view = owner.publish_many({"alpha": 1, "beta": 2}.items())
    published_duplicates = owner.publish_many((("dup", "first"), ("dup", "second")))
    invalid_pair = owner.publish_many((HostileInitKey(),))

    assert dict(frozen_duplicate_mapping) == {"1": "int-key", "1#1": "text-key"}
    assert published_from_view["alpha"] == 1
    assert published_from_view["beta"] == 2
    assert published_duplicates["dup"] == "first"
    assert published_duplicates["dup#1"] == "second"
    assert invalid_pair["invalid_init_item_0"]["unavailable_reason"] == "invalid_init_item"
    assert HostileInitKey.touched == 0

def test_stage1750_runtime_init_state_source_has_no_deepcopy_or_best_effort_materialization():
    source = read_python_file(Path("Virus_Scan/runtime/init_state.py"))

    assert "deepcopy" not in source
    assert "dict(value)" not in source
    assert "vars(" not in source
    assert "getattr(" not in source
    assert "object.__getattribute__(value" not in source
