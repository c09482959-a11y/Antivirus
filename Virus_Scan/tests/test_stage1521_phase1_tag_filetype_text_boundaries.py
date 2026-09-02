from __future__ import annotations

from Virus_Scan.contracts.tag_evidence import (
    contextual_dangerous_anchor_hits,
    evidence_level_for_tag,
    safe_tag_evidence_text,
)
from Virus_Scan.detection.contracts.filetype_context import filetype_validation_context
from Virus_Scan.detection.contracts.string_predicates import validate_high_risk_tag
from Virus_Scan.detection.contracts.tag_validation import validate_tags_for_path
from Virus_Scan.utils.tagging import canonical_tag_name, normalize_tags, ordered_unique_tags


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.strip_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves raw caller __str__ was used
        raise AssertionError("caller-owned __str__ was invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves raw caller strip was used
        self.strip_calls += 1
        raise AssertionError("caller-owned strip was invoked")

    def __bool__(self):  # pragma: no cover - failure proves raw caller truthiness was used
        raise AssertionError("caller-owned bool was invoked")


def assert_not_probed(*values: HostileText) -> None:
    for value in values:
        assert value.strip_calls == 0


def test_stage1521_shared_tag_evidence_detaches_hostile_text_before_strip_or_bool():
    tag = HostileText(" powershell_exec ")
    assert safe_tag_evidence_text(tag) == " powershell_exec "

    level, weight = evidence_level_for_tag(
        tag,
        strings_blob=HostileText(" powershell -enc payload "),
        api_calls=(HostileText(" CreateProcess "),),
        ordered_events=(HostileText(" powershell_exec "),),
    )

    assert level == "ordered_chain"
    assert weight == 0.85
    assert_not_probed(tag)


def test_stage1521_utils_tag_normalization_detaches_hostile_text():
    raw = HostileText(" Stage Hit:PowerShell Exec ")
    normalized = normalize_tags([raw])
    ordered = ordered_unique_tags([raw])
    canonical = canonical_tag_name(raw)

    assert normalized == ["Stage Hit:PowerShell Exec"]
    assert ordered == ["Stage Hit:PowerShell Exec"]
    assert canonical == "stage_hit:powershell_exec"
    assert_not_probed(raw)


def test_stage1521_detection_tag_validation_detaches_tag_source_and_predicate_text():
    tag = HostileText(" custom_behavior_marker ")
    source = HostileText(" raw ")
    path = HostileText(" game/script.rpy ")

    assert validate_high_risk_tag(tag, HostileText(" benign context "), path) is True
    assert validate_tags_for_path([tag], path=path, strings_blob=HostileText(" benign context "), source=source) == ["custom_behavior_marker"]
    assert_not_probed(tag, source, path)


def test_stage1521_dangerous_anchor_and_filetype_context_detach_hostile_text():
    anchor = HostileText(" powershell_exec ")
    hits = contextual_dangerous_anchor_hits([anchor])
    assert "powershell_exec" in hits

    engine = HostileText(" renpy ")
    path = HostileText(" game/script.rpy ")
    context = filetype_validation_context(engine, path)
    assert context["extension"] == "rpy"
    assert isinstance(context["extension"], str)
    assert type(context["extension"]) is str
    assert_not_probed(anchor, engine, path)
