from pathlib import Path

from Virus_Scan.detection.models.evidence import StageCollectorMerge
from Virus_Scan.detection.models.stage_value_utils import safe_detection_bool


class HostileBool:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")


class HostileGetRecord:
    touched = 0

    def __init__(self):
        self.unavailable_reason = "hostile"

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not call get")

    def __getattr__(self, name):
        type(self).touched += 1
        raise RuntimeError("do not getattr")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")


class HostileMapping(dict):
    touched = 0

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not call dict subclass get")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not call dict subclass items")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")


def test_stage1601_safe_detection_bool_rejects_hostile_truthiness_without_calling_it():
    HostileBool.touched = 0

    value, evidence = safe_detection_bool(
        HostileBool(),
        default_bool=False,
        reason="hostile_bool_rejected",
    )

    assert value is False
    assert evidence["unavailable_reason"] == "hostile_bool_rejected"
    assert HostileBool.touched == 0


def test_stage1601_safe_detection_bool_has_no_fallback_keyword_route():
    source = (Path(__file__).resolve().parents[1] / "detection/models/stage_value_utils.py").read_text(
        encoding="utf-8"
    )

    assert "**default_overrides" not in source
    assert '"fallback" in default_overrides' not in source


def test_stage1601_stage_collector_merge_does_not_probe_hostile_getters_or_mapping_hooks():
    HostileGetRecord.touched = 0
    HostileMapping.touched = 0

    merged = StageCollectorMerge(
        tags=(HostileGetRecord(), HostileMapping({"unavailable_reason": "hidden"})),
        metadata={},
        suspicious=HostileBool(),
        errors=(HostileGetRecord(), HostileMapping({"unavailable_reason": "hidden"})),
    )

    assert HostileGetRecord.touched == 0
    assert HostileMapping.touched == 0
    assert merged.suspicious is False
    assert "<unavailable>" in merged.tags
    assert "stage_collector_suspicious_unavailable" in str(merged.errors)
