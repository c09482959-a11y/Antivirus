from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.detection.scoring.adaptive.availability import (
    available_feature_probability,
    available_model_signal_probability,
    probability_feature_unavailable_reason,
)
from Virus_Scan.detection.scoring.adaptive.boundary_values import (
    adaptive_invalid_flag_reason,
    adaptive_mapping_get,
)


class HostileKey:
    touched = 0

    def __hash__(self):  # pragma: no cover - failure proves caller hook was invoked
        type(self).touched += 1
        raise AssertionError("caller-owned key __hash__ invoked")

    def __eq__(self, other):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned key __eq__ invoked")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned key __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned key __repr__ invoked")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned key __format__ invoked")


class HostileFieldName(HostileKey):
    pass


def test_stage2019_adaptive_mapping_rejects_hostile_keys_before_dict_lookup() -> None:
    HostileKey.touched = 0
    key = HostileKey()

    assert adaptive_mapping_get({"score": 0.9}, key, "default") == "default"
    assert available_model_signal_probability({"score": 0.9}, key) == 0.0
    assert HostileKey.touched == 0


def test_stage2019_probability_feature_key_paths_do_not_format_hostile_key() -> None:
    HostileKey.touched = 0
    key = HostileKey()

    assert probability_feature_unavailable_reason({"p_graph": 0.9, "graph_ready": True}, key) == "invalid_probability_feature_key"
    assert available_feature_probability({"p_graph": 0.9, "graph_ready": True}, key, None) == 0.0
    assert HostileKey.touched == 0


def test_stage2019_adaptive_invalid_flag_reason_rejects_hostile_field_name_without_formatting() -> None:
    HostileFieldName.touched = 0

    assert adaptive_invalid_flag_reason(object(), HostileFieldName()) == "invalid_unknown_flag"
    assert HostileFieldName.touched == 0


def test_stage2019_adaptive_availability_sources_do_not_reintroduce_key_formatting() -> None:
    availability_source = read_python_file(Path("Virus_Scan/detection/scoring/adaptive/availability.py"))
    boundary_source = read_python_file(Path("Virus_Scan/detection/scoring/adaptive/boundary_values.py"))

    forbidden_fragments = (
        "f'{key}",
        "f'{key_text}",
        "f'{base}",
        "f'degraded_{base}",
        "f'confidence_degraded_{base}",
        'f"invalid_{field_name}_flag"',
    )
    offenders = [fragment for fragment in forbidden_fragments if fragment in availability_source or fragment in boundary_source]
    assert offenders == []
