from __future__ import annotations

from Virus_Scan.detection.contracts.progress import has_any_tag, stage_progress
from Virus_Scan.detection.models.detection_result import (
    build_fast_benign_detection_result,
    build_fast_suspicious_detection_result,
)


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.str_calls = 0
        obj.strip_calls = 0
        obj.lower_calls = 0
        obj.bool_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves caller-owned __str__ was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves caller-owned strip was used
        self.strip_calls += 1
        raise AssertionError("caller-owned strip was invoked")

    def lower(self, *args, **kwargs):  # pragma: no cover - failure proves caller-owned lower was used
        self.lower_calls += 1
        raise AssertionError("caller-owned lower was invoked")

    def __bool__(self):  # pragma: no cover - failure proves caller-owned bool was used
        self.bool_calls += 1
        raise AssertionError("caller-owned bool was invoked")


class HostileBool:
    def __bool__(self):  # pragma: no cover - failure proves hostile truthiness escaped
        raise RuntimeError("truthiness unavailable")


class HostileMapping(dict):
    def __bool__(self):  # pragma: no cover - mapping truthiness is not needed for projection
        raise AssertionError("caller-owned mapping bool was invoked")


def h(value: str) -> HostileText:
    return HostileText(value)


def assert_no_hooks(*values: HostileText) -> None:
    for value in values:
        assert value.str_calls == 0
        assert value.strip_calls == 0
        assert value.lower_calls == 0
        assert value.bool_calls == 0


def test_stage1524_progress_and_tag_lookup_detach_string_subclasses() -> None:
    stage = h("model_scan")
    tag = h("memory_write")
    needle = h("memory_write")

    progress = stage_progress(stage, inc=1, bytes_delta=2)

    assert progress["stage"] == "model_scan"
    assert has_any_tag([tag], needle) is True
    assert type(progress["stage"]) is str
    assert_no_hooks(stage, tag, needle)


def test_stage1524_fast_benign_result_detaches_exact_text_and_bool_boundaries() -> None:
    path = h("game/script.rpy")
    tag = h("image_asset")
    reason = h("cache hit")
    constraint_key = h("policy")
    constraint_value = h("enabled")

    result = build_fast_benign_detection_result(
        path=path,
        score=1.0,
        confidence=0.4,
        tags=[tag],
        prefilter_tags=[tag],
        effective_stage=h("prefilter"),
        reason=reason,
        version=h("stage1524"),
        constraints=HostileMapping({constraint_key: constraint_value}),
        model_evidence={},
        yaralight_active=HostileBool(),
    )

    assert result["node"] == "game/script.rpy"
    assert result["prefilter_tags"] == ["image_asset"]
    assert result["explanation"]["reasons"] == ["cache hit"]
    assert result["explanation"]["constraints"]["policy"] == "enabled"
    assert result["explanation"]["constraints"]["yaralight_active"] is False
    assert type(result["node"]) is str
    assert type(result["prefilter_tags"][0]) is str
    assert_no_hooks(path, tag, reason, constraint_key, constraint_value)


def test_stage1524_fast_suspicious_result_detaches_profile_reason_and_hits() -> None:
    path = h("payload.exe")
    tag = h("process_injection")
    profile = h("renpy")
    reason = h("explicit chain")
    hit = h("CreateRemoteThread")

    result = build_fast_suspicious_detection_result(
        path=path,
        score=81.0,
        tags=[tag],
        active_profile=profile,
        reason=reason,
        version=h("stage1524"),
        constraints=HostileMapping({h("cap"): h("static_anchor")}),
        heuristic_hits=[hit],
        confidence=0.8,
        attack_hit=hit,
        model_evidence={},
    )

    assert result["classification"] == "malicious"
    assert result["tags"] == ["process_injection"]
    assert result["profile_selection"]["active_profile"] == "renpy"
    assert result["heuristics"]["hits"] == ["CreateRemoteThread"]
    assert result["attack_intelligence"]["hits"] == ["CreateRemoteThread"]
    assert_no_hooks(path, tag, profile, reason, hit)

from Virus_Scan.detection.profiles.selection import build_detection_profile_context


def test_stage1524_profile_selection_reasons_detach_string_subclasses() -> None:
    reason = h("selected custom profile")

    def reporter(_engine_context, *, path, tags, strings_blob):
        return {
            "active_profile": "renpy",
            "baseline_suppression_allowed": False,
            "reasons": (reason,),
        }

    context = build_detection_profile_context(
        engine_context={"renpy": 1.0},
        path=h("game/script.rpy"),
        tags=(h("renpy_script"),),
        strings_blob=h("label start:"),
        engine_confidence_reporter=reporter,
    )

    assert context.active_profile == "renpy"
    assert context.selection_reasons == ("selected custom profile",)
    assert type(context.selection_reasons[0]) is str
    assert_no_hooks(reason)
