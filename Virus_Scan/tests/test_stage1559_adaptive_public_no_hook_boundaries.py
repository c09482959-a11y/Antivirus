from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.detection.scoring.adaptive.availability import available_model_signal_probability
from Virus_Scan.detection.scoring.adaptive.boundary_values import adaptive_mapping_get, adaptive_reason_text
from types import MappingProxyType

from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_event_sequence,
    adaptive_public_mapping,
    adaptive_public_mapping_field,
    adaptive_public_node_reference,
    adaptive_public_sequence,
    adaptive_public_text_with_reason,
)


class HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - failure proves caller hook was invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ invoked")


class HostileIterable:
    touched = 0

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __iter__ invoked")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ invoked")


class HostileList(list):
    touched = 0

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned list subclass __iter__ invoked")

    def __len__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned list subclass __len__ invoked")


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, key):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __getitem__ invoked")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __iter__ invoked")

    def __len__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __len__ invoked")

    def get(self, key, default=None):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned get invoked")

    def items(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned items invoked")


class HostileStr(str):
    touched = 0

    def __new__(cls, value):
        return str.__new__(cls, value)

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned str subclass __str__ invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned str subclass strip invoked")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned str subclass truthiness invoked")


def test_stage1559_adaptive_public_text_rejects_unknown_objects_without_stringifying():
    HostileText.touched = 0
    value = HostileText()

    assert adaptive_public_text_with_reason(value, default="fallback") == (
        "fallback",
        "text_coercion_failed",
    )
    assert adaptive_reason_text(value) == "unreadable_model_signal_reason"
    assert HostileText.touched == 0


def test_stage1559_adaptive_public_text_preserves_safe_str_subclass_without_hooks():
    HostileStr.touched = 0
    text = HostileStr(" unavailable ")

    assert adaptive_public_text_with_reason(text) == ("unavailable", None)
    assert adaptive_reason_text(text) == "unavailable"
    assert HostileStr.touched == 0


def test_stage1559_adaptive_public_sequences_reject_hostile_iterables_without_iterating():
    HostileIterable.touched = 0
    HostileList.touched = 0

    assert adaptive_public_sequence(HostileIterable()) == ()
    assert adaptive_public_event_sequence(HostileIterable()) == ()
    assert adaptive_public_sequence(HostileList(["x"])) == ()
    assert adaptive_public_event_sequence(HostileList(["x"])) == ()

    assert HostileIterable.touched == 0
    assert HostileList.touched == 0


def test_stage1559_adaptive_public_mapping_rejects_hostile_mapping_without_mapping_hooks():
    HostileMapping.touched = 0
    mapping = HostileMapping()

    result = adaptive_public_mapping(mapping)
    child = adaptive_public_mapping_field(mapping, "child")

    assert result["adaptive_input_rejected"] is True
    assert result["adaptive_input_reason"] == "adaptive_input_mapping_rejected"
    assert result["unavailable_reason"] == "adaptive_input_mapping_rejected"
    assert child == result
    assert adaptive_mapping_get(mapping, "score", "default") == "default"
    assert available_model_signal_probability(mapping, "score") == 0.0

    assert HostileMapping.touched == 0


def test_stage1559_adaptive_public_mapping_rejects_dict_subclass_without_builtin_hook_escape():
    class NoisyDict(dict):
        touched = 0

        def get(self, key, default=None):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned dict subclass get invoked")

        def items(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned dict subclass items invoked")

        def __iter__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned dict subclass iter invoked")

    source = NoisyDict({"score": 0.75, "child": {"ready": True}})

    result = adaptive_public_mapping(source)
    child = adaptive_public_mapping_field(source, "child")

    assert result["adaptive_input_rejected"] is True
    assert result["adaptive_input_reason"] == "adaptive_input_materialization_failed"
    assert child == result
    assert adaptive_mapping_get(source, "score") == 0.75
    assert available_model_signal_probability(source, "score") == 0.75
    assert NoisyDict.touched == 0


def test_stage1581_adaptive_public_mapping_preserves_exact_empty_and_valid_builtin_dicts():
    assert adaptive_public_mapping(None) == {}
    assert adaptive_public_mapping({}) == {}
    assert adaptive_public_mapping({"score": 0.75, "child": {"ready": True}}) == {
        "score": 0.75,
        "child": {"ready": True},
    }
    assert adaptive_public_mapping_field({"child": {"ready": True}}, "child") == {"ready": True}


def test_stage2023_adaptive_public_mapping_suffixes_duplicate_keys_without_fstrings():
    result = adaptive_public_mapping({b"dup": 1, "dup": 2})

    assert result == {"dup": 1, "dup#1": 2}


def test_stage1581_adaptive_public_mapping_rejects_unsupported_scalar_with_evidence():
    value = object()
    result = adaptive_public_mapping(value)

    assert result["adaptive_input_rejected"] is True
    assert result["adaptive_input_reason"] == "adaptive_input_not_mapping"
    assert result["value_type"] == "object"
    assert result["final_json_must_record"] is True




def test_stage1601_adaptive_public_node_reference_returns_exact_text_not_caller_object():
    class HostilePath(str):
        touched = 0

        def __new__(cls, value):
            return str.__new__(cls, value)

        def __str__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned node __str__ invoked")

        def __repr__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned node __repr__ invoked")

        def __bool__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned node truthiness invoked")

    node = HostilePath("sample.exe")
    node_for_model, reason = adaptive_public_node_reference(node)

    assert type(node_for_model) is str
    assert node_for_model == "sample.exe"
    assert reason is None
    assert HostilePath.touched == 0

def test_stage1581_adaptive_public_node_reference_propagates_mapping_rejection():
    HostileMapping.touched = 0
    node, reason = adaptive_public_node_reference(HostileMapping())

    assert node is None
    assert reason == "adaptive_input_mapping_rejected"
    assert HostileMapping.touched == 0


def test_stage1581_adaptive_public_mappingproxy_invalid_backing_rejects_without_hooks():
    class NoisyDict(dict):
        touched = 0

        def items(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned mappingproxy backing items invoked")

        def __iter__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned mappingproxy backing iter invoked")

    source = MappingProxyType(NoisyDict({"score": 1.0}))
    result = adaptive_public_mapping(source)

    assert result["adaptive_input_rejected"] is True
    assert result["adaptive_input_reason"] == "adaptive_input_materialization_failed"
    assert NoisyDict.touched == 0


def test_stage2023_adaptive_public_inputs_source_removed_audited_legacy_paths():
    source = read_python_file(Path("Virus_Scan/detection/scoring/adaptive/public_inputs.py"))

    assert 'key_text = f"{key_text}#{index}"' not in source
    assert "legacy neutral" not in source
