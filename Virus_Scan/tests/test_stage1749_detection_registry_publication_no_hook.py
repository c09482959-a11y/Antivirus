from __future__ import annotations

import ast
from collections import Counter, defaultdict
from pathlib import Path
from types import MappingProxyType

from Virus_Scan.detection.registries.detection_constants import (
    DetectionRegistrySnapshot,
    init_detection_constants,
)
from Virus_Scan.detection.registries.publication import (
    freeze_registry_publication,
    publish_init_values,
)


class HostileRegistryDict(dict):
    touched = 0

    def items(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not call items")


class HostileRegistryKey:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileRegistryDeepcopy:
    touched = 0

    def __deepcopy__(self, memo):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not deepcopy")


def test_stage1749_registry_publication_rejects_hostile_mapping_without_items_hook():
    HostileRegistryDict.touched = 0

    frozen = freeze_registry_publication(HostileRegistryDict({"unsafe": "value"}))

    assert HostileRegistryDict.touched == 0
    assert frozen["unavailable_reason"] == "non_materializable_detection_registry_value"
    assert frozen["value_type"] == "HostileRegistryDict"


def test_stage1749_registry_publication_rejects_hostile_key_without_string_hooks():
    HostileRegistryKey.touched = 0

    frozen = freeze_registry_publication({HostileRegistryKey(): "value"})

    assert HostileRegistryKey.touched == 0
    evidence = frozen["detection_registry_key_0"]
    assert evidence["unavailable_reason"] == "invalid_key_type"
    assert evidence["value_type"] == "HostileRegistryKey"


def test_stage1749_registry_publication_rejects_unsupported_object_without_deepcopy_hook():
    HostileRegistryDeepcopy.touched = 0

    frozen = freeze_registry_publication(HostileRegistryDeepcopy())

    assert HostileRegistryDeepcopy.touched == 0
    assert frozen["unavailable_reason"] == "non_materializable_detection_registry_value"
    assert frozen["value_type"] == "HostileRegistryDeepcopy"


def test_stage1749_publish_init_values_rejects_hostile_name_without_string_hooks():
    HostileRegistryKey.touched = 0

    frozen = publish_init_values(((HostileRegistryKey(), "value"),))

    assert HostileRegistryKey.touched == 0
    evidence = frozen["detection_registry_name_0"]
    assert evidence["unavailable_reason"] == "invalid_key_type"
    assert evidence["value_type"] == "HostileRegistryKey"


def test_stage1749_registry_publication_preserves_valid_nested_immutability_and_snapshot():
    nested = {"registry": {"aliases": ["one"]}}
    frozen = freeze_registry_publication(MappingProxyType(nested))
    nested["registry"]["aliases"].append("two")

    assert frozen["registry"]["aliases"] == ("one",)
    constants = init_detection_constants()
    assert isinstance(constants["DETECTION_REGISTRY_SNAPSHOT"], DetectionRegistrySnapshot)


def test_stage1749_registry_publication_preserves_counter_and_defaultdict_snapshots():
    counter = Counter({"beta": 2, "alpha": 1})
    nested = defaultdict(int)
    nested["seen"] = 3

    frozen_counter = freeze_registry_publication(counter)
    frozen_defaultdict = freeze_registry_publication(nested)

    assert dict(frozen_counter) == {"alpha": 1, "beta": 2}
    assert dict(frozen_defaultdict) == {"seen": 3}


def test_stage1749_registry_publication_source_has_no_unsafe_boundary_calls():
    source_path = Path("Virus_Scan/detection/registries/publication.py")
    source = source_path.read_text()
    tree = ast.parse(source)
    forbidden_snippets = (
        "return False",
        "return None",
        "return tuple(dict.items(value))",
        'out_key = key_text if key_text not in frozen else f"{key_text}#{index}"',
        'return f"invalid_detection_registry_item_{index}",',
    )
    assert [snippet for snippet in forbidden_snippets if snippet in source] == []
    assert [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
    forbidden_name_calls = {"str", "repr", "format", "dict", "vars", "getattr"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in forbidden_name_calls
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"items", "keys", "values", "get", "__deepcopy__"}:
                segment = ast.get_source_segment(source, node) or ""
                assert (
                    isinstance(node.func.value, ast.Name) and node.func.value.id in {"dict", "type"}
                ) or segment.startswith("sys.modules.get(")
