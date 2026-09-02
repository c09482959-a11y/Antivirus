from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.detection.profiles import selection
from Virus_Scan.detection.profiles.selection import build_detection_profile_context



class HostileConfidenceError(RuntimeError):
    touched_str = 0
    touched_repr = 0
    touched_format = 0

    def __str__(self):
        type(self).touched_str += 1
        raise RuntimeError("hostile __str__ must not execute")

    def __repr__(self):
        type(self).touched_repr += 1
        raise RuntimeError("hostile __repr__ must not execute")

    def __format__(self, spec):
        type(self).touched_format += 1
        raise RuntimeError("hostile __format__ must not execute")


class HostilePath:
    touched_str = 0
    touched_repr = 0

    def __str__(self):
        type(self).touched_str += 1
        raise RuntimeError("hostile path __str__ must not execute")

    def __repr__(self):
        type(self).touched_repr += 1
        raise RuntimeError("hostile path __repr__ must not execute")


class HostileDefaultMapping:
    touched_iter = 0
    touched_items = 0
    touched_bool = 0

    def __iter__(self):
        type(self).touched_iter += 1
        raise RuntimeError("hostile default mapping iteration must not execute")

    def items(self):
        type(self).touched_items += 1
        raise RuntimeError("hostile default mapping items must not execute")

    def __bool__(self):
        type(self).touched_bool += 1
        raise RuntimeError("hostile default mapping truthiness must not execute")


def _raising_confidence_reporter(*_args, **_kwargs):
    raise HostileConfidenceError("confidence boom")


def test_profile_confidence_error_fallback_does_not_stringify_hostile_error():
    HostileConfidenceError.touched_str = 0
    HostileConfidenceError.touched_repr = 0
    HostileConfidenceError.touched_format = 0

    context = build_detection_profile_context(
        engine_context={"renpy": 1.0},
        path="game/renpy/script.rpy",
        tags=(),
        strings_blob="",
        engine_confidence_reporter=_raising_confidence_reporter,
    )

    confidence = context.engine_confidence
    assert confidence["degraded"] is True
    assert confidence["confidence_degraded"] is True
    assert confidence["error"] == "HostileConfidenceError"
    assert confidence["error_category"] == "HostileConfidenceError"
    assert confidence["failure_evidence"][0]["message"] == "confidence boom"
    assert confidence["scan_integrity"]["json_record_required"] is True
    assert confidence["scan_integrity"]["replay_record_required"] is True
    assert HostileConfidenceError.touched_str == 0
    assert HostileConfidenceError.touched_repr == 0
    assert HostileConfidenceError.touched_format == 0


def test_profile_confidence_failure_context_rejects_hostile_path_without_hooks():
    HostileConfidenceError.touched_str = 0
    HostileConfidenceError.touched_repr = 0
    HostileConfidenceError.touched_format = 0
    HostilePath.touched_str = 0
    HostilePath.touched_repr = 0

    context = build_detection_profile_context(
        engine_context={"renpy": 1.0},
        path=HostilePath(),
        tags=(),
        strings_blob="",
        engine_confidence_reporter=_raising_confidence_reporter,
    )

    failure = context.engine_confidence["failure_evidence"][0]
    assert failure["affected_context"] == ""
    assert failure["error_category"] == "HostileConfidenceError"
    assert failure["json_record_required"] is True
    assert failure["replay_record_required"] is True
    assert HostilePath.touched_str == 0
    assert HostilePath.touched_repr == 0
    assert HostileConfidenceError.touched_str == 0
    assert HostileConfidenceError.touched_repr == 0
    assert HostileConfidenceError.touched_format == 0


def test_profile_context_default_mapping_rejects_unknown_mapping_without_hooks():
    HostileDefaultMapping.touched_iter = 0
    HostileDefaultMapping.touched_items = 0
    HostileDefaultMapping.touched_bool = 0

    snapshot = selection._mapping_snapshot(None, default=HostileDefaultMapping())

    assert snapshot == {}
    assert HostileDefaultMapping.touched_iter == 0
    assert HostileDefaultMapping.touched_items == 0
    assert HostileDefaultMapping.touched_bool == 0


def test_profile_selection_source_has_no_raw_error_stringification():
    source = read_python_file(Path("Virus_Scan/detection/profiles/selection.py"))
    assert "str(error)" not in source
    assert "no_hook_type_name(error)" in source
    assert "_confidence_error_text(error)" in source
    assert "dict(default)" not in source
    assert "return fallback" not in source
    assert "fallback" not in source
    assert "text, _evidence = safe_detection_text(" not in source
