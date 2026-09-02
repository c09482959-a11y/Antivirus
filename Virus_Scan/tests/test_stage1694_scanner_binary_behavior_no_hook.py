"""Stage 1694: scanner binary behavior/evidence helpers reject hostile text hooks."""
from __future__ import annotations

from Virus_Scan.scanners.binary_behavior_detectors import detect_env_var_abuse
from Virus_Scan.scanners.binary_pe_evidence import immutable_tag_tuple


class _HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("do not format")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")


class _HostileIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


def test_detect_env_var_abuse_rejects_hostile_tag_hooks() -> None:
    _HostileText.touched = 0
    score, hits = detect_env_var_abuse(
        (_HostileText(), "registry_mod", "process_exec"),
    )

    assert _HostileText.touched == 0
    assert score == 6.0
    assert hits == ["registry → execution coupling"]


def test_detect_env_var_abuse_rejects_hostile_containers_before_iteration() -> None:
    _HostileIterable.touched = 0
    score, hits = detect_env_var_abuse(_HostileIterable())

    assert _HostileIterable.touched == 0
    assert score == 0.0
    assert hits == []


def test_immutable_pe_tag_tuple_rejects_hostile_tag_hooks_with_evidence() -> None:
    _HostileText.touched = 0
    tags = immutable_tag_tuple((_HostileText(), "pe_file"))

    assert _HostileText.touched == 0
    assert "pe_file" in tags
    assert "tag_normalization_failure_evidence" in tags
    assert "detection_stage_degraded" in tags
