"""Stage 1695: scanner binary text/semantic boundaries reject hostile hooks."""
from __future__ import annotations

import pytest

from Virus_Scan.scanners.binary_behavior_detectors import detect_ransomware_file_rename_heuristic
from Virus_Scan.scanners.binary_behavior_semantics import (
    EffectiveEvidenceScoreRequest,
    evidence_level_for_tag,
    tag_behavior_bucket,
    tag_effective_evidence_score,
)
from Virus_Scan.scanners.binary_text_signals import binary_regex_match, binary_text_has_any


class _HostileText:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("do not format")


class _HostileIterable:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


def test_binary_text_signal_helpers_reject_hostile_text_and_needles_without_hooks() -> None:
    _HostileText.touched = 0
    _HostileIterable.touched = 0

    assert binary_text_has_any(_HostileText(), ("powershell",)) is False
    assert binary_text_has_any("powershell", _HostileIterable()) is False
    with pytest.raises(TypeError):
        binary_regex_match(_HostileText(), "powershell")
    with pytest.raises(TypeError):
        binary_regex_match("powershell", _HostileText())

    assert _HostileText.touched == 0
    assert _HostileIterable.touched == 0


def test_binary_behavior_semantics_reject_hostile_tag_contexts_without_hooks() -> None:
    _HostileText.touched = 0
    _HostileIterable.touched = 0

    assert tag_behavior_bucket(_HostileText()) == "other_behavior"
    evidence, confidence = evidence_level_for_tag(
        _HostileText(),
        strings_blob=_HostileText(),
        api_calls=_HostileIterable(),
        ordered_events=_HostileIterable(),
    )
    result = tag_effective_evidence_score(EffectiveEvidenceScoreRequest(
        "sample.exe",
        _HostileText(),
        strings_blob=_HostileText(),
        api_calls=_HostileIterable(),
        ordered_events=_HostileIterable(),
    ))

    assert evidence == "unsafe_behavior_tag_rejected"
    assert confidence == 0.0
    assert result["ready"] is False
    assert result["reason"] == "unsafe_behavior_tag_rejected"
    assert result["failure_evidence_recorded"] is True
    assert result["effective_score"] == 0.0
    assert _HostileText.touched == 0
    assert _HostileIterable.touched == 0


def test_binary_behavior_semantics_preserve_exact_primitive_inputs() -> None:
    assert binary_text_has_any("powershell DownloadString", ("powershell", "cmd.exe")) is True
    assert binary_regex_match(r"powershell\s+download", "PowerShell Download") is True
    assert tag_behavior_bucket("process_exec") == "os_execution"
    evidence, confidence = evidence_level_for_tag(
        "process_exec",
        strings_blob="process exec",
        api_calls=("CreateProcessW",),
        ordered_events=("process_exec",),
    )
    assert evidence == "confirmed_timeline"
    assert confidence == 0.85


def test_ransomware_heuristic_rejects_hostile_blob_and_tags_without_hooks() -> None:
    _HostileText.touched = 0
    _HostileIterable.touched = 0

    result = detect_ransomware_file_rename_heuristic(_HostileText(), tags=_HostileIterable())

    assert result["score"] == 0.0
    assert result["tags"] == []
    assert result["hits"] == []
    assert result["failure_evidence_recorded"] is True
    assert result["reason"] == "unsafe_ransomware_strings_blob_rejected"
    assert _HostileText.touched == 0
    assert _HostileIterable.touched == 0
