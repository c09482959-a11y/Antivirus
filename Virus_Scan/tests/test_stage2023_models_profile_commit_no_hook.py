from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path
from unittest.mock import patch

from Virus_Scan.models.profiles import commit as profile_commit


class HostileLearningResult(dict):
    touched = 0

    def get(self, key, default=None):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("profile commit must not call caller-owned result get")

    def items(self):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("profile commit must not call caller-owned result items")


def _patch_commit_dependencies(result):
    return (
        patch.object(profile_commit, "infer_profile_engine", return_value=("renpy", {"active_profile": "renpy"})),
        patch.object(profile_commit, "commit_promoted_learning", return_value=result),
    )


def test_stage2023_update_profile_from_scan_result_preserves_exact_learning_result() -> None:
    result = {"learned": True, "reason": "ok", "baseline": {"files": 2}}
    engine_patch, commit_patch = _patch_commit_dependencies(result)

    with engine_patch, commit_patch:
        payload = profile_commit.update_profile_from_scan_result("game.rpy", ("renpy_script",), verdict="clean")

    assert payload["baseline"] == {"files": 2}
    assert payload["learning"] == {"learned": True, "reason": "ok"}
    assert payload["engine"] == "renpy"


def test_stage2023_update_profile_from_scan_result_rejects_hostile_learning_result_hooks() -> None:
    HostileLearningResult.touched = 0
    result = HostileLearningResult({"learned": True, "baseline": {"files": 2}})
    engine_patch, commit_patch = _patch_commit_dependencies(result)

    with (
        engine_patch,
        commit_patch,
        patch.object(profile_commit, "get_extension_baseline", return_value={"fallback": True}),
    ):
        payload = profile_commit.update_profile_from_scan_result("game.rpy", ("renpy_script",), verdict="clean")

    assert payload["baseline"] == {"fallback": True}
    assert payload["learning"] == {
        "degraded": True,
        "unavailable_reason": "profile_update_learning_result_invalid",
    }
    assert HostileLearningResult.touched == 0


def test_stage2023_profile_commit_source_uses_no_hook_result_mapping_reader() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/commit.py"))

    assert "result.get(" not in source
    assert "result.items()" not in source
    assert "profile_mapping_get" in source
    assert "profile_mapping_items" in source
