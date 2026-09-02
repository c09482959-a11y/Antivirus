from collections.abc import Mapping
from types import MappingProxyType

from Virus_Scan.detection.scoring.adaptive.availability import (
    availability_aware_layer_probability_summary,
)
from Virus_Scan.detection.scoring.adaptive.confidence import (
    adaptive_learned_model_confidence,
)
from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_mapping,
    adaptive_public_mapping_with_state,
    adaptive_public_sequence,
)


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, _key):
        type(self).touched += 1
        raise RuntimeError("mapping getitem hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("mapping iter hook executed")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("mapping len hook executed")


class HostileBytes(bytes):
    touched = 0

    def __new__(cls):
        return bytes.__new__(cls, b"hostile")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("bytes iter hook executed")

    def __bytes__(self):
        type(self).touched += 1
        raise RuntimeError("bytes conversion hook executed")


class HostileNestedValue:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("nested str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("nested repr hook executed")


def test_stage1756_absent_and_valid_empty_adaptive_inputs_have_distinct_states() -> None:
    absent, absent_state = adaptive_public_mapping_with_state(None)
    empty, empty_state = adaptive_public_mapping_with_state({})

    assert absent == {}
    assert empty == {}
    assert absent_state == "adaptive_input_not_provided"
    assert empty_state == "adaptive_input_valid_empty"

    absent_summary = availability_aware_layer_probability_summary(None)
    empty_summary = availability_aware_layer_probability_summary({})
    assert absent_summary["adaptive_input_state"] == "adaptive_input_not_provided"
    assert empty_summary["adaptive_input_state"] == "adaptive_input_valid_empty"


def test_stage1756_hostile_mapping_rejection_is_explicit_and_non_scoring() -> None:
    HostileMapping.touched = 0
    hostile = HostileMapping()

    mapping, state = adaptive_public_mapping_with_state(hostile)
    confidence = adaptive_learned_model_confidence(
        profile_signal=hostile,
        markov_signal=hostile,
        cluster_signal=hostile,
    )

    assert mapping["adaptive_input_rejected"] is True
    assert state == "adaptive_input_mapping_rejected"
    assert confidence == 0.0
    assert HostileMapping.touched == 0


def test_stage1756_mapping_proxy_nested_failure_is_explicit_without_hooks() -> None:
    HostileNestedValue.touched = 0

    mapping = adaptive_public_mapping(
        MappingProxyType({"nested": HostileNestedValue()})
    )

    assert mapping["nested"]["unavailable_reason"] == (
        "non_materializable_adaptive_public_input_value"
    )
    assert mapping["nested"]["value"] is None
    assert HostileNestedValue.touched == 0


def test_stage1756_bytes_subclass_is_rejected_without_conversion_or_iteration() -> None:
    HostileBytes.touched = 0

    assert adaptive_public_sequence(HostileBytes()) == ()
    assert HostileBytes.touched == 0
