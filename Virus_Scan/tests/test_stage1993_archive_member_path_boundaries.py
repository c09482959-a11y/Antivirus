from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scanners.archives.member_scan import scan_archive_member
from Virus_Scan.scanners.archives.path_safety import safe_archive_child_path
from Virus_Scan.scanners.archives.rpa_member_no_hook import rpa_member_owned_text, rpa_member_input_path
from Virus_Scan.scanners.archives.rpa_member_text_tags import append_behavior_tags


class HostilePath:
    def __str__(self) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned __str__ executed")

    def __repr__(self) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned __repr__ executed")

    def __format__(self, format_spec: str) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned __format__ executed")

    def __bool__(self) -> bool:  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned __bool__ executed")

    def __fspath__(self) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned __fspath__ executed")


class HostileMemberName(HostilePath):
    pass


def test_stage1993_scan_archive_member_rejects_unsafe_path_before_hooks() -> None:
    tags, suspicious = scan_archive_member(
        HostilePath(),  # type: ignore[arg-type]
        0,
        archive_scanner=lambda path, depth: (["unexpected_inner_scan"], False),
    )

    assert suspicious is True
    assert "archive_member_path_unsafe" in tags
    assert "archive_member_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags
    assert "unexpected_inner_scan" not in tags


def test_stage1993_safe_archive_child_path_keeps_rejection_explicit_without_hooks(tmp_path: Path) -> None:
    assert safe_archive_child_path(tmp_path, HostileMemberName()) is None  # type: ignore[arg-type]
    assert safe_archive_child_path(tmp_path, "nested/file.txt") == (tmp_path / "nested/file.txt").resolve()


def test_stage1993_rpa_member_text_boundary_rejects_hostile_text_without_hooks() -> None:
    text, reason = rpa_member_owned_text(HostilePath(), "rpa_member_hostile_text")
    assert text == ""
    assert reason == "rpa_member_hostile_text"
    path_text, path_reason = rpa_member_input_path(HostilePath())
    assert path_text == ""
    assert path_reason == "rpa_member_path_unsafe"

    tags: list[str] = []
    append_behavior_tags(tags, HostilePath())
    assert tags == [
        "rpa_member_behavior_text_unsafe",
        "rpa_failure_evidence_recorded",
        "archive_final_json_must_record",
    ]


def test_stage1993_archive_source_snippets_are_removed() -> None:
    member_scan = read_python_file(Path("Virus_Scan/scanners/archives/member_scan.py"))
    path_safety = read_python_file(Path("Virus_Scan/scanners/archives/path_safety.py"))
    rpa_no_hook = read_python_file(Path("Virus_Scan/scanners/archives/rpa_member_no_hook.py"))
    rpa_behavior = read_python_file(Path("Virus_Scan/scanners/archives/rpa_member_behavior.py"))
    rpa_text_tags = read_python_file(Path("Virus_Scan/scanners/archives/rpa_member_text_tags.py"))

    assert "text = safe_read_text(path, max_size=_ARCHIVE_POLICY.member_text_max_size)" not in member_scan
    assert "path, _reason = safe_archive_child_path_with_reason(root, member_name)" not in path_safety
    assert "def safe_text(value: object, reason: str) -> tuple[str, str]:" not in rpa_no_hook
    assert "text, reason = safe_text(path, \"rpa_member_path_unsafe\")" not in rpa_no_hook
    assert "text, text_reason = safe_text(value, \"rpa_member_meta_failure_unsafe\")" not in rpa_no_hook
    assert "member_text, member_reason = safe_text(member_name, \"rpa_member_name_unsafe\")" not in rpa_behavior
    assert "sub_text, sub_reason = safe_text(sub_kind, \"rpa_member_subkind_unsafe\")" not in rpa_behavior
    assert "text, text_reason = safe_text(value, \"rpa_member_record_text_unsafe\")" not in rpa_behavior
    assert "low, reason = safe_text(text, \"rpa_member_behavior_text_unsafe\")" not in rpa_text_tags
