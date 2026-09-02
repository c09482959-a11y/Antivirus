from __future__ import annotations

import ast
import json
from pathlib import Path

from Virus_Scan.publication.json_finalization.error_fields import compact_error_runtime_fields
from Virus_Scan.publication.json_finalization.record_fields import record_duration_seconds
from Virus_Scan.publication.json_finalization.success_context import compact_success_context

_RECORD_FIELDS_PATH = (
    Path(__file__).resolve().parents[2]
    / "Virus_Scan/publication/json_finalization/record_fields.py"
)


class HostileDurationValue:
    touched = 0

    @property
    def text(self):  # pragma: no cover - failure proves property probing returned
        type(self).touched += 1
        raise AssertionError("duration text property touched")

    @property
    def value(self):  # pragma: no cover - failure proves property probing returned
        type(self).touched += 1
        raise AssertionError("duration value property touched")

    def __float__(self):  # pragma: no cover - failure proves numeric coercion returned
        type(self).touched += 1
        raise AssertionError("duration __float__ touched")

    def __int__(self):  # pragma: no cover - failure proves numeric coercion returned
        type(self).touched += 1
        raise AssertionError("duration __int__ touched")

    def __str__(self):  # pragma: no cover - failure proves string hook returned
        type(self).touched += 1
        raise AssertionError("duration __str__ touched")

    def __repr__(self):  # pragma: no cover - failure proves repr hook returned
        type(self).touched += 1
        raise AssertionError("duration __repr__ touched")


def _reset() -> None:
    HostileDurationValue.touched = 0


def test_stage1723_duration_missing_absence_is_explicitly_owned_not_literal_return() -> None:
    assert record_duration_seconds({}) == 0.0

    success_context = compact_success_context({"classification": "clean", "tags": []})
    assert success_context["scan_duration_seconds"] == 0.0

    error_context = {"errors": [], "tags": [], "reasons": []}
    runtime_fields = compact_error_runtime_fields({}, error_context)
    assert runtime_fields["scan_duration_seconds"] == 0.0
    assert runtime_fields["duration_seconds"] == 0.0
    assert runtime_fields["duration"] == 0.0
    assert runtime_fields["timing"] == {"scan_duration_seconds": 0.0}


def test_stage1723_duration_invalid_top_level_value_emits_evidence_without_hooks() -> None:
    _reset()
    hostile = HostileDurationValue()

    duration = record_duration_seconds({"duration": hostile})

    assert duration["model_signal_projection_failed"] is True
    assert duration["reason"] == "unsafe_numeric_value_rejected"
    assert duration["value_type"] == "HostileDurationValue"
    assert HostileDurationValue.touched == 0
    assert json.dumps(duration, sort_keys=True)


def test_stage1723_duration_invalid_timing_value_emits_evidence_without_hooks() -> None:
    _reset()
    hostile = HostileDurationValue()

    duration = record_duration_seconds({"timing": {"duration_seconds": hostile}})

    assert duration["model_signal_projection_failed"] is True
    assert duration["reason"] == "unsafe_numeric_value_rejected"
    assert duration["value_type"] == "HostileDurationValue"
    assert HostileDurationValue.touched == 0
    assert json.dumps(duration, sort_keys=True)


def test_stage1723_record_duration_has_no_literal_zero_default_return() -> None:
    tree = ast.parse(_RECORD_FIELDS_PATH.read_text(encoding="utf-8"), filename=str(_RECORD_FIELDS_PATH))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != "record_duration_seconds":
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and isinstance(child.value, ast.Constant):
                if child.value.value == 0.0:
                    offenders.append(f"{_RECORD_FIELDS_PATH.name}:{child.lineno}:literal_zero_duration_return")
    assert offenders == []
