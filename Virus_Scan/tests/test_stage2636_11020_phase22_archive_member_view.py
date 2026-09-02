from __future__ import annotations

from pathlib import Path
import tarfile
import zipfile

import pytest

from Virus_Scan.scanners.archives.member_scan import scan_archive_member
from Virus_Scan.scanners.archives.member_view import (
    detect_archive_container_kind,
    inspect_archive_member,
)
from Virus_Scan.scanners.archives.scanner import scan_archive_file
from Virus_Scan.tests.support.native_filesystem_alias import create_native_file_alias
from Virus_Scan.tests.support.static_inventory import read_python_file


def test_phase22_member_view_owns_bounded_raw_text_and_both_edges(tmp_path: Path) -> None:
    sample = tmp_path / "member.bin"
    payload = b"MZ" + b"A" * 30 + b"TAILMZ"
    sample.write_bytes(payload)

    view = inspect_archive_member(str(sample), probe_bytes=8, text_max_size=16)

    assert view.container_kind == "unknown"
    assert view.size == len(payload)
    assert view.prefix == payload[:8]
    assert view.suffix == payload[-8:]
    assert view.raw == payload[:16]
    assert view.text == payload[:16].decode("utf-8", errors="ignore")
    assert view.truncated is True


def test_phase22_member_view_classifies_zip_and_tar_without_content_projection(tmp_path: Path) -> None:
    zip_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("member.txt", "payload")
    tar_path = tmp_path / "sample.tar"
    member = tmp_path / "member.txt"
    member.write_text("payload", encoding="utf-8")
    with tarfile.open(tar_path, "w") as archive:
        archive.add(member, arcname="member.txt")

    zip_view = inspect_archive_member(str(zip_path), probe_bytes=512, text_max_size=1024)
    tar_view = inspect_archive_member(str(tar_path), probe_bytes=512, text_max_size=1024)

    assert detect_archive_container_kind(str(zip_path)) == "zip"
    assert detect_archive_container_kind(str(tar_path)) == "tar"
    assert zip_view.container_kind == "zip"
    assert tar_view.container_kind == "tar"
    assert (zip_view.raw, zip_view.text, zip_view.prefix, zip_view.suffix) == (b"", "", b"", b"")
    assert (tar_view.raw, tar_view.text, tar_view.prefix, tar_view.suffix) == (b"", "", b"", b"")


def test_phase22_member_scan_passes_exact_container_kind_to_recursive_owner(tmp_path: Path) -> None:
    nested = tmp_path / "nested.bin"
    with zipfile.ZipFile(nested, "w") as archive:
        archive.writestr("member.txt", "payload")
    observed: list[tuple[str, int, str]] = []

    def classified_scanner(path: str, depth: int, kind: str) -> tuple[list[str], bool]:
        observed.append((path, depth, kind))
        return (["classified_nested_archive"], False)

    tags, suspicious = scan_archive_member(str(nested), 3, classified_scanner)

    assert suspicious is False
    assert observed == [(str(nested), 3, "zip")]
    assert "classified_nested_archive" in tags


def test_phase22_member_view_rejects_symlink_without_following_target(tmp_path: Path) -> None:
    target = tmp_path / "outside.bin"
    target.write_bytes(b"MZpayload")
    alias = create_native_file_alias(tmp_path / "alias.bin", target).path

    with pytest.raises(ValueError, match="archive_member_not_regular_file"):
        inspect_archive_member(str(alias), probe_bytes=512, text_max_size=1024)


def test_phase22_root_identity_failure_remains_fail_closed(tmp_path: Path) -> None:
    missing = tmp_path / "missing.zip"

    tags, suspicious = scan_archive_file(str(missing))

    assert suspicious is True
    assert "archive_identity_error" in tags
    assert "archive_final_json_must_record" in tags


def test_phase22_member_payload_consumes_owned_bytes_without_reopening() -> None:
    member_source = read_python_file(Path("Virus_Scan/scanners/archives/member_scan.py"))
    payload_source = read_python_file(Path("Virus_Scan/scanners/archives/payloads.py"))

    assert "safe_read_text(" not in member_source
    assert "_read_member_edges(" not in member_source
    assert "read_file_bytes" not in payload_source
    assert "archive_member_payload_tags(" in member_source
    assert "path_text, view.raw, view.text" in member_source
