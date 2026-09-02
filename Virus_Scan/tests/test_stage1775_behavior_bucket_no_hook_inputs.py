
"""Stage 1775 behavior bucket no-hook input boundary regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.detection.scoring.behavior.bucket_validation import (
    behavior_bucket_validation,
    credential_family_boost,
)
from Virus_Scan.utils.tagging import DETECTION_STAGE_DEGRADED_TAG, TAG_NORMALIZATION_FAILURE_EVIDENCE


class HostileText:
    str_calls = 0
    bool_calls = 0
    iter_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("hostile __str__ must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("hostile __bool__ must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("hostile __iter__ must not execute")


class HostileIterable:
    str_calls = 0
    bool_calls = 0
    iter_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("hostile __str__ must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("hostile __bool__ must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("hostile __iter__ must not execute")


def _reset() -> None:
    for cls in (HostileText, HostileIterable):
        cls.str_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0


def test_behavior_bucket_validation_rejects_hostile_engine_path_without_hooks() -> None:
    _reset()

    result = behavior_bucket_validation(HostileText(), HostileText(), tags=("process_exec",))

    assert HostileText.str_calls == 0
    assert HostileText.bool_calls == 0
    assert HostileText.iter_calls == 0
    assert result["engine_extension"] == "other:"
    assert result["records"]
    assert result["filetype_validation"]["context"]["execution_capability"] == "unknown"


def test_behavior_bucket_validation_rejects_hostile_tag_container_without_hooks() -> None:
    _reset()

    result = behavior_bucket_validation("renpy", "game.rpa", tags=HostileIterable())

    assert HostileIterable.str_calls == 0
    assert HostileIterable.bool_calls == 0
    assert HostileIterable.iter_calls == 0
    tags = {record["tag"] for record in result["records"]}
    assert tags == {"detection_observation_unavailable"}


def test_credential_family_boost_rejects_hostile_tags_and_blob_without_hooks() -> None:
    _reset()

    result = credential_family_boost(HostileIterable(), strings_blob=HostileText())

    assert HostileIterable.str_calls == 0
    assert HostileIterable.bool_calls == 0
    assert HostileIterable.iter_calls == 0
    assert HostileText.str_calls == 0
    assert HostileText.bool_calls == 0
    assert result["degraded"] is True
    assert "credential_tag_input_rejected" in result["reasons"]
    assert any(reason.startswith("credential_blob_unavailable") for reason in result["reasons"])
    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in result["tags"]
    assert DETECTION_STAGE_DEGRADED_TAG in result["tags"]


def test_credential_family_boost_preserves_exact_falsey_string_content_without_str_hook() -> None:
    class FalseyExactString(str):
        def __new__(cls):
            return str.__new__(cls, "login data cryptunprotectdata lsass minidumpwritedump")

        def __bool__(self):
            return False

        def __str__(self):
            raise RuntimeError("no caller-owned string conversion")

    result = credential_family_boost(("credential_access", "lsass_access"), strings_blob=FalseyExactString())

    assert result["score"] > 0.0
    assert "credential_stealer_behavior" in result["tags"]
    assert result["degraded"] is False


def test_stage1775_behavior_bucket_source_forbids_raw_hookable_conversions() -> None:
    source = read_python_file(Path("Virus_Scan/detection/scoring/behavior/bucket_validation.py"))
    tree = ast.parse(source)
    forbidden = (
        "str(\"\" if tag is None else tag)",
        "tags or ()",
        "str(tag).lower()",
        "str(engine or 'other')",
        "str(context.get('extension') or '')",
        "str(\"\" if strings_blob is None else strings_blob)",
        "{str(tag).lower() for tag in tags or ()}",
        "combined_bucket = safe_clamp(",
        "credential_blob_unavailable:{blob_reason}",
        "credential tags: {sorted(hits)}",
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
    assert [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
