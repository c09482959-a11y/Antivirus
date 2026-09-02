from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path, PurePosixPath

from Virus_Scan.models.profiles.common import PROFILE_TEXT_UNAVAILABLE, profile_public_path_text, profile_safe_text



class HostileProfilePath(PurePosixPath):
    __module__ = "pathlib"
    touched = 0

    def as_posix(self):
        type(self).touched += 1
        raise RuntimeError("do not call as_posix")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not fspath")


def test_stage1751_profile_safe_text_rejects_path_subclass_without_path_hooks():
    HostileProfilePath.touched = 0

    assert profile_safe_text(HostileProfilePath("/tmp/evil"), replacement="profile_unavailable") == "profile_unavailable"
    assert profile_safe_text(HostileProfilePath("/tmp/evil")) == PROFILE_TEXT_UNAVAILABLE

    assert HostileProfilePath.touched == 0


def test_stage1751_profile_public_path_text_rejects_path_subclass_without_path_hooks():
    HostileProfilePath.touched = 0

    text, reason = profile_public_path_text(HostileProfilePath("/tmp/evil"), replacement="fallback")

    assert text == "fallback"
    assert reason == "profile_public_path_invalid"
    assert HostileProfilePath.touched == 0


def test_stage1751_profile_safe_text_preserves_exact_stdlib_path_text():
    path = PurePosixPath("/tmp/game/archive.rpa")

    assert profile_safe_text(path) == "/tmp/game/archive.rpa"
    assert profile_public_path_text(path) == ("/tmp/game/archive.rpa", None)


def test_stage1751_profile_common_does_not_call_instance_path_methods():
    source = read_python_file(Path("Virus_Scan/models/profiles/common.py"))

    assert "value.as_posix" not in source
    assert "str(value)" not in source
    assert "repr(value)" not in source
    assert "format(value" not in source
