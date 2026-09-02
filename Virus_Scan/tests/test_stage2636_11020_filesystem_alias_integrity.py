from __future__ import annotations

import os
from pathlib import Path

import pytest

from Virus_Scan.contracts.runtime_platform_identity import runtime_platform_identity
from Virus_Scan.runtime.api import (
    path_contains_filesystem_alias,
    stat_result_is_filesystem_alias,
    windows_file_attributes_indicate_alias,
)
from Virus_Scan.tests.support.native_filesystem_alias import (
    create_native_directory_alias,
    create_native_file_alias,
)


def test_filesystem_alias_owner_accepts_one_real_native_path(tmp_path: Path) -> None:
    directory = tmp_path / "real"
    directory.mkdir()
    path = directory / "payload.bin"
    path.write_bytes(b"payload")

    assert path_contains_filesystem_alias(path) is False
    assert stat_result_is_filesystem_alias(path.lstat()) is False


def test_filesystem_alias_owner_rejects_native_directory_alias(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    alias = create_native_directory_alias(tmp_path / "alias", target)

    assert path_contains_filesystem_alias(alias.path) is True
    assert stat_result_is_filesystem_alias(alias.entry.lstat()) is True


def test_filesystem_alias_owner_rejects_native_file_alias_chain(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"sentinel")
    alias = create_native_file_alias(tmp_path / "alias.bin", target)

    assert alias.path.read_bytes() == b"sentinel"
    assert path_contains_filesystem_alias(alias.path) is True


def test_filesystem_alias_owner_has_exact_windows_reparse_attribute_contract() -> None:
    assert windows_file_attributes_indicate_alias(0) is False
    assert windows_file_attributes_indicate_alias(0x400) is True
    assert windows_file_attributes_indicate_alias(0x410) is True
    with pytest.raises(TypeError, match="filesystem_alias_windows_attributes_invalid"):
        windows_file_attributes_indicate_alias(True)


def test_native_alias_fixture_uses_frozen_platform_capability(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    alias = create_native_directory_alias(tmp_path / "alias", target)
    operating_system = runtime_platform_identity().operating_system

    assert operating_system in ("linux", "windows")
    assert alias.kind == (
        "posix_symlink" if operating_system == "linux" else "windows_directory_junction"
    )
    assert stat_result_is_filesystem_alias(os.lstat(alias.entry)) is True
