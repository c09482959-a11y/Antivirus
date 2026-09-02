from __future__ import annotations

from pathlib import Path

from Virus_Scan.models.api.text_boundary import public_api_contract_text
from Virus_Scan.contracts.library_baseline import (
    is_known_python_runtime_library_path,
    is_python_runtime_binary_path,
    is_renpy_engine_runtime_source_path,
    is_runtime_or_engine_library_path,
    library_baseline_hard_proof_status,
    library_baseline_has_hard_proof,
)


class HostilePathLike:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not call fspath")


class HostileText:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")


class HostileTags:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not call iter")


class HostileTag:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")


def test_library_baseline_path_helpers_reject_hostile_pathlike_without_hooks() -> None:
    path = HostilePathLike()
    assert is_renpy_engine_runtime_source_path(path, "") is False
    assert is_known_python_runtime_library_path(path, "") is False
    assert is_python_runtime_binary_path(path) is False
    assert is_runtime_or_engine_library_path(path) is False
    assert HostilePathLike.touched == 0


def test_library_baseline_text_probe_rejects_hostile_text_without_hooks() -> None:
    text = HostileText()
    assert is_renpy_engine_runtime_source_path("other/core.py", text) is False
    assert is_known_python_runtime_library_path("other/bootstrap.py", text) is False
    status, hard = library_baseline_hard_proof_status(tags=(), strings_blob=text)
    assert (status, hard) == ("no_hard_proof", False)
    assert HostileText.touched == 0


def test_library_baseline_tags_reject_unknown_iterables_and_items_without_hooks() -> None:
    tags = HostileTags()
    assert library_baseline_has_hard_proof(tags=tags, strings_blob="") is False
    assert HostileTags.touched == 0

    assert library_baseline_has_hard_proof(tags=[HostileTag()], strings_blob="") is False
    assert HostileTag.touched == 0


def test_library_baseline_preserves_primitive_positive_paths() -> None:
    assert is_known_python_runtime_library_path("renpy/display/core.py", "") is True
    assert is_python_runtime_binary_path("renpy/lib/python.exe") is True
    assert is_runtime_or_engine_library_path("Game_Data/Managed/UnityPlayer.dll") is True
    assert library_baseline_has_hard_proof(tags=["known_bad_hash"], strings_blob="") is True
    assert library_baseline_has_hard_proof(tags=[], strings_blob="powershell -enc payload") is True


def test_public_model_api_text_boundary_does_not_call_caller_owned_fspath() -> None:
    pathlike = HostilePathLike()
    text, reason = public_api_contract_text(pathlike, default_text="<blocked>")
    assert (text, reason) == ("<blocked>", "unreadable_public_contract_text")
    assert HostilePathLike.touched == 0

    path_text, path_reason = public_api_contract_text(Path("renpy/display/core.py"))
    assert path_text == "renpy/display/core.py"
    assert path_reason is None
