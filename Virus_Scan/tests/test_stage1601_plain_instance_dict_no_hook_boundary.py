from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict, no_hook_text
from Virus_Scan.contracts.api_behavior import api_call_values
from Virus_Scan.contracts.behavior_rarity import behavior_rarity_from_flow
from Virus_Scan.contracts.call_graph_projection import immutable_api_call_graph
from Virus_Scan.contracts.yara_hits import normalize_yara_rule_name
from Virus_Scan.detection.models.stage_value_utils import freeze_detection_value
from Virus_Scan.models.api.text_boundary import public_api_contract_text
from Virus_Scan.models.profiles.common import profile_safe_text
from Virus_Scan.models.temporal.text_boundary import TEMPORAL_TEXT_UNAVAILABLE, temporal_boundary_text
from Virus_Scan.publication.json_finalization.base_projection import bounded_list, bounded_signal_value, canonical_tag_list
from Virus_Scan.publication.json_finalization.projection_text import safe_projection_text
from Virus_Scan.publication.json_finalization.truthiness import iterable_values_without_truthiness


class HostileDictDescriptor:
    touches = 0

    @property
    def __dict__(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("__dict__ property must not execute")

    @property
    def text(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("text property must not execute")

    @property
    def values(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("values property must not execute")

    def __str__(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("str hook must not execute")

    def __repr__(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("repr hook must not execute")

    def __iter__(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("iter hook must not execute")


class PlainWrapper:
    def __init__(self, value: str) -> None:
        self.text = value

    def __str__(self):  # pragma: no cover - regression asserts no execution
        raise RuntimeError("wrapper str hook must not execute")


def test_stage1601_canonical_plain_instance_dict_rejects_hostile_dict_descriptor_without_touching_it() -> None:
    HostileDictDescriptor.touches = 0
    hostile = HostileDictDescriptor()

    assert no_hook_plain_instance_dict(hostile) is None
    assert no_hook_text(hostile) == ("", "unsafe_text_value_rejected")
    assert HostileDictDescriptor.touches == 0


def test_stage1601_publication_projection_rejects_hostile_dict_descriptor_without_touching_it() -> None:
    HostileDictDescriptor.touches = 0
    hostile = HostileDictDescriptor()

    text, reason = safe_projection_text(hostile)
    signal = bounded_signal_value(hostile)
    as_list = bounded_list(hostile)
    tag_list = canonical_tag_list(hostile)
    values = iterable_values_without_truthiness(hostile)

    assert (text, reason) == ("", "final_json_text_unavailable")
    assert signal["model_signal_projection_failed"] is True
    assert signal["reason"] == "final_json_text_unavailable"
    assert as_list[0]["model_signal_projection_failed"] is True
    assert tag_list == ["<HostileDictDescriptor final_json_text_unavailable>"]
    assert values == []
    assert HostileDictDescriptor.touches == 0


def test_stage1601_model_detection_contract_boundaries_reject_hostile_dict_descriptor_without_touching_it() -> None:
    HostileDictDescriptor.touches = 0
    hostile = HostileDictDescriptor()

    frozen = freeze_detection_value(hostile)

    assert profile_safe_text(hostile, replacement="profile_fallback") == "profile_fallback"
    assert temporal_boundary_text(hostile) == TEMPORAL_TEXT_UNAVAILABLE
    assert public_api_contract_text(hostile, default_text="api_fallback") == (
        "api_fallback",
        "unreadable_public_contract_text",
    )
    assert frozen["degraded"] is True
    assert frozen["unavailable_reason"] == "detection_scalar_unavailable"
    assert tuple(api_call_values(hostile)) == ("api_name_text_unavailable",)
    assert dict(immutable_api_call_graph(hostile)) == {}
    assert behavior_rarity_from_flow(hostile, {}) == 0.0
    assert normalize_yara_rule_name(hostile) == ""
    assert HostileDictDescriptor.touches == 0


def test_stage1601_plain_wrapper_text_fields_still_work_after_dict_descriptor_lock() -> None:
    wrapper = PlainWrapper("owned_text")

    assert no_hook_plain_instance_dict(wrapper) == {"text": "owned_text"}
    assert no_hook_text(wrapper) == ("owned_text", "")
    assert safe_projection_text(wrapper) == ("owned_text", "")
    assert profile_safe_text(wrapper, replacement="") == "owned_text"
    assert temporal_boundary_text(wrapper) == "owned_text"
    assert public_api_contract_text(wrapper) == ("owned_text", None)
