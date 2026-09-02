from pathlib import Path

import pytest

from Virus_Scan.runtime.platform_filesystem_durability import (
    FilesystemDurabilityError,
    durable_activate_directory,
    durable_replace_regular_file,
    flush_directory,
    flush_existing_regular_file,
    flush_open_writable_file,
)


def test_platform_durability_flushes_closed_file_and_directory(tmp_path: Path) -> None:
    target = tmp_path / "payload.bin"
    target.write_bytes(b"durable")

    flush_existing_regular_file(target)
    flush_directory(tmp_path)

    assert target.read_bytes() == b"durable"


def test_platform_durability_flushes_caller_owned_open_file(tmp_path: Path) -> None:
    target = tmp_path / "payload.bin"
    with target.open("wb") as stream:
        stream.write(b"durable")
        stream.flush()
        flush_open_writable_file(stream.fileno())
        assert stream.closed is False

    assert target.read_bytes() == b"durable"


def test_platform_durability_replaces_regular_file_atomically(tmp_path: Path) -> None:
    source = tmp_path / "payload.tmp"
    destination = tmp_path / "payload.bin"
    source.write_bytes(b"new")
    destination.write_bytes(b"old")

    durable_replace_regular_file(source, destination)

    assert not source.exists()
    assert destination.read_bytes() == b"new"


def test_platform_durability_activates_new_directory_without_replacement(tmp_path: Path) -> None:
    source = tmp_path / "staging"
    destination = tmp_path / "active"
    source.mkdir()
    (source / "manifest.json").write_text("{}", encoding="utf-8")

    durable_activate_directory(source, destination)

    assert not source.exists()
    assert (destination / "manifest.json").read_text(encoding="utf-8") == "{}"


def test_platform_durability_rejects_wrong_entry_kinds(tmp_path: Path) -> None:
    regular = tmp_path / "regular.bin"
    directory = tmp_path / "directory"
    regular.write_bytes(b"x")
    directory.mkdir()

    with pytest.raises(FilesystemDurabilityError, match="filesystem_durability_file_invalid"):
        flush_existing_regular_file(directory)
    with pytest.raises(FilesystemDurabilityError, match="filesystem_durability_directory_invalid"):
        flush_directory(regular)
    with pytest.raises(FilesystemDurabilityError, match="filesystem_durability_source_file_invalid"):
        durable_replace_regular_file(directory, tmp_path / "destination.bin")


def test_platform_durability_rejects_directory_replacement(tmp_path: Path) -> None:
    source = tmp_path / "staging"
    destination = tmp_path / "active"
    source.mkdir()
    destination.mkdir()

    with pytest.raises(FilesystemDurabilityError, match="filesystem_durability_destination_preexisting"):
        durable_activate_directory(source, destination)

    assert source.is_dir()
    assert destination.is_dir()
