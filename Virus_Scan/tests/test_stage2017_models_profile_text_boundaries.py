import ast
from pathlib import Path

import pytest

from Virus_Scan.models.profiles.common import (
    PROFILE_TEXT_UNAVAILABLE,
    profile_first_reason,
    profile_public_path_text,
    profile_public_yara_hits,
    profile_safe_text,
)
from Virus_Scan.models.profiles.context import engine_extension_key
from Virus_Scan.models.profiles.evidence import merge_profile_subsignal_unavailable
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence
from Virus_Scan.models.profiles.timeline import timeline_transitions


ROOT = Path(__file__).resolve().parents[2]
PROFILE_ROOT = ROOT / "Virus_Scan/models/profiles"
PROFILE_FILES = (
    PROFILE_ROOT / "common.py",
    PROFILE_ROOT / "context.py",
    PROFILE_ROOT / "evidence.py",
    PROFILE_ROOT / "learning.py",
    PROFILE_ROOT / "extension_learning.py",
    PROFILE_ROOT / "timeline.py",
)


class HostileText:
    def __str__(self):
        raise AssertionError("str hook must not run")

    def __repr__(self):
        raise AssertionError("repr hook must not run")

    def __format__(self, spec):
        raise AssertionError("format hook must not run")


class HostilePath:
    def __fspath__(self):
        raise AssertionError("fspath hook must not run")

    def __str__(self):
        raise AssertionError("str hook must not run")


class HostileMapping(dict):
    def items(self):
        raise AssertionError("mapping items hook must not run")


def test_profile_text_helpers_use_replacement_without_calling_hooks():
    assert profile_safe_text(HostileText(), replacement="profile_unavailable") == "profile_unavailable"
    assert profile_first_reason(None, HostileText(), replacement="profile_reason") == PROFILE_TEXT_UNAVAILABLE
    path_text, reason = profile_public_path_text(HostilePath(), replacement="safe-path")
    assert path_text == "safe-path"
    assert reason == "profile_public_path_invalid"
    with pytest.raises(TypeError):
        profile_safe_text(HostileText(), fallback="legacy_profile_unavailable")
    with pytest.raises(TypeError):
        profile_first_reason(None, fallback="legacy_reason")
    with pytest.raises(TypeError):
        profile_public_path_text(HostilePath(), fallback="legacy_path")


def test_profile_public_yara_hits_and_context_key_are_primitive_built():
    assert profile_public_yara_hits((HostileText(),), "bad_yara") == (("<unreadable_yara_hit_0>",), None)
    assert engine_extension_key("renpy", "script.rpy") == "renpy:.rpy"


def test_profile_subsignal_unavailable_uses_primitive_field_construction():
    unavailable = {}
    failures = []
    signal = {
        "degraded": True,
        "unavailable_reason": HostileText(),
        "model_failures": (),
    }
    merge_profile_subsignal_unavailable("support", signal, unavailable, failures)
    assert unavailable == {"support": PROFILE_TEXT_UNAVAILABLE}
    assert failures == []


def test_profile_chain_and_timeline_keys_are_primitive_without_fstrings():
    evidence = evaluate_chain_evidence(tags=("phase_one",))
    assert evidence.decisions == ()
    events, transitions, behaviors, behavior_transitions = timeline_transitions(
        ({"tag": "download"}, {"tag": "exec"}),
        max_events=8,
    )
    assert events == ["download", "exec"]
    assert transitions == ["download->exec"]
    assert behavior_transitions == ["network->os_execution"]


def test_stage2017_profile_source_no_legacy_fallback_or_fstring_rows():
    forbidden = (
        "**named_replacements",
        "_PROFILE_REPLACEMENT_ALIAS_KEY",
        "_profile_replacement_value",
        "def profile_safe_text(value, *, fallback=''):",
        "def profile_public_path_text(value, reason='profile_public_path_invalid', *, fallback=''):",
        "def profile_first_reason(*values, fallback='profile_unavailable'):",
        "profile_safe_text(item, fallback=f'<unreadable_yara_hit_{index}>'",
        "return f\"{engine_text}:{normalize_profile_extension(file_path)}\"",
        "record[f'{support_field_text}_unavailable_reason'] = f'invalid_{support_field_text}'",
        "normal_chains.add(f'{phase}:{matched[0]}')",
        "suspicious_chains.add(f'{phase}:multi_signal_chain')",
        "transitions = [f'{events[i]}->{events[i + 1]}' for i in range(len(events) - 1)]",
        "behavior_transitions = [f'{behaviors[i]}->{behaviors[i + 1]}' for i in range(len(behaviors) - 1)]",
    )
    for path in PROFILE_FILES:
        source = path.read_text(encoding="utf-8")
        for snippet in forbidden:
            assert snippet not in source
        tree = ast.parse(source)
        assert not [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]


def test_stage2017_profile_helpers_have_no_fallback_keyword_callers():
    helper_names = {"profile_safe_text", "profile_public_path_text", "profile_first_reason"}
    fallback_calls = []
    for path in PROFILE_ROOT.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                function_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                function_name = node.func.attr
            else:
                function_name = ""
            if function_name not in helper_names:
                continue
            if any(keyword.arg == "fallback" for keyword in node.keywords):
                fallback_calls.append((path.name, node.lineno, function_name))
    assert fallback_calls == []
