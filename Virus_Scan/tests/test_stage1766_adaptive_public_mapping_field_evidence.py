from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.detection.scoring.adaptive.confidence import adaptive_learned_model_confidence
from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_mapping_field,
)


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, key):  # noqa: ANN001, ANN204
        type(self).touched += 1
        raise RuntimeError("getitem hook should not execute")

    def __iter__(self):  # noqa: ANN204
        type(self).touched += 1
        raise RuntimeError("iter hook should not execute")

    def __len__(self) -> int:
        type(self).touched += 1
        raise RuntimeError("len hook should not execute")


def test_stage1766_mapping_field_distinguishes_absent_empty_and_missing_child() -> None:
    absent = adaptive_public_mapping_field(None, "profile")
    empty = adaptive_public_mapping_field({}, "profile")
    missing = adaptive_public_mapping_field({"markov": {"ready": True}}, "profile")

    assert "unavailable_reason" not in absent
    assert absent["adaptive_input_reason"] == "adaptive_input_not_provided"
    assert absent["adaptive_input_field"] == "profile"
    assert absent["final_json_must_record"] is True

    assert "unavailable_reason" not in empty
    assert empty["adaptive_input_reason"] == "adaptive_input_field_missing"
    assert empty["adaptive_input_field"] == "profile"

    assert "unavailable_reason" not in missing
    assert missing["adaptive_input_reason"] == "adaptive_input_field_missing"
    assert missing["adaptive_input_field"] == "profile"


def test_stage1766_mapping_field_rejected_parent_does_not_become_empty_dict() -> None:
    HostileMapping.touched = 0
    rejected = adaptive_public_mapping_field(HostileMapping(), "profile")

    assert rejected["adaptive_input_rejected"] is True
    assert rejected["adaptive_input_reason"] == "adaptive_input_mapping_rejected"
    assert HostileMapping.touched == 0


def test_stage1766_mapping_field_preserves_valid_child_mapping() -> None:
    child = adaptive_public_mapping_field({"profile": {"profile_ready": True}}, "profile")

    assert child == {"profile_ready": True}


def test_stage1766_mapping_field_unavailable_evidence_does_not_inflate_confidence() -> None:
    unavailable_profile = adaptive_public_mapping_field({}, "profile")

    assert adaptive_learned_model_confidence(profile_signal=unavailable_profile) == 0.0
