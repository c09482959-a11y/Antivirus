from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scanners.archives.path_safety import (
    safe_archive_child_path,
    safe_archive_child_path_with_reason,
)


class HostileArchiveMemberName:
    bool_touched = 0
    str_touched = 0
    fspath_touched = 0

    def __bool__(self):
        type(self).bool_touched += 1
        raise RuntimeError("archive member __bool__ must not execute")

    def __str__(self):
        type(self).str_touched += 1
        raise RuntimeError("archive member __str__ must not execute")

    def __fspath__(self):
        type(self).fspath_touched += 1
        raise RuntimeError("archive member __fspath__ must not execute")


class HostileArchiveRoot:
    bool_touched = 0
    str_touched = 0
    fspath_touched = 0

    def __bool__(self):
        type(self).bool_touched += 1
        raise RuntimeError("archive root __bool__ must not execute")

    def __str__(self):
        type(self).str_touched += 1
        raise RuntimeError("archive root __str__ must not execute")

    def __fspath__(self):
        type(self).fspath_touched += 1
        raise RuntimeError("archive root __fspath__ must not execute")


def _reset_hostile_counters() -> None:
    for cls in (HostileArchiveMemberName, HostileArchiveRoot):
        cls.bool_touched = 0
        cls.str_touched = 0
        cls.fspath_touched = 0


def test_stage1691_archive_member_name_rejects_hostile_hooks(tmp_path: Path) -> None:
    _reset_hostile_counters()
    target, reason = safe_archive_child_path_with_reason(tmp_path, HostileArchiveMemberName())

    assert target is None
    assert reason.startswith("unsafe_archive_member_name_rejected:")
    assert HostileArchiveMemberName.bool_touched == 0
    assert HostileArchiveMemberName.str_touched == 0
    assert HostileArchiveMemberName.fspath_touched == 0


def test_stage1691_archive_root_rejects_hostile_fspath_hooks() -> None:
    _reset_hostile_counters()
    target, reason = safe_archive_child_path_with_reason(HostileArchiveRoot(), "member.txt")

    assert target is None
    assert reason.startswith("unsafe_archive_root_rejected:")
    assert HostileArchiveRoot.bool_touched == 0
    assert HostileArchiveRoot.str_touched == 0
    assert HostileArchiveRoot.fspath_touched == 0


def test_stage1691_archive_path_safety_preserves_existing_contract(tmp_path: Path) -> None:
    assert safe_archive_child_path(tmp_path, "safe/member.txt") == (tmp_path / "safe/member.txt").resolve()
    assert safe_archive_child_path(tmp_path, "../escape.txt") is None
    target, reason = safe_archive_child_path_with_reason(tmp_path, "/absolute/escape.txt")
    assert target is None
    assert reason == "archive_member_absolute_path_rejected"


def test_stage1691_archive_path_safety_source_has_no_member_hook_shortcuts() -> None:
    source = read_python_file(Path("Virus_Scan/scanners/archives/path_safety.py"))
    assert "str(member_name or" not in source
    assert "Path(root)" not in source
    assert "os.fspath" not in source
