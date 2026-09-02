from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
import os
import zipfile
from pathlib import Path

import pytest

from Virus_Scan.runtime.resource_paths import resource_dir, state_file
from Virus_Scan.runtime.resource_quotas import (
    ResourceQuotaExceeded,
    RuntimeBudget,
    extract_zip_member_with_quota,
)


class HostilePathText:
    touched = 0

    def __str__(self) -> str:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile path string hook executed")

    def __repr__(self) -> str:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile path repr hook executed")

    def __format__(self, spec: str) -> str:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile path format hook executed")

    def __fspath__(self) -> str:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile path fspath hook executed")


class HostileNumber:
    touched = 0

    def __int__(self) -> int:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile number int hook executed")

    def __str__(self) -> str:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile number string hook executed")

    def __repr__(self) -> str:  # pragma: no cover - failure if called
        type(self).touched += 1
        raise AssertionError("hostile number repr hook executed")


class DummyZip:
    def open(self, member: object, mode: str = "r") -> object:  # pragma: no cover - failure if called
        raise AssertionError("zip open should not run after rejected root")


def test_stage1977_resource_path_public_routes_reject_hostile_text_without_hooks() -> None:
    HostilePathText.touched = 0

    with pytest.raises(ValueError, match="resource_dir_name_rejected"):
        resource_dir(HostilePathText())
    with pytest.raises(ValueError, match="state_file_name_rejected"):
        state_file(HostilePathText())

    assert HostilePathText.touched == 0


def test_stage1977_zip_extraction_rejects_hostile_root_before_fspath(tmp_path: Path) -> None:
    HostilePathText.touched = 0
    member = zipfile.ZipInfo("asset.txt")
    member.file_size = 1
    member.compress_size = 1

    with pytest.raises(ValueError, match="archive_root_unsupported"):
        extract_zip_member_with_quota(DummyZip(), member, HostilePathText())

    assert HostilePathText.touched == 0


def test_stage1977_runtime_budget_rejects_hostile_number_without_hooks() -> None:
    HostileNumber.touched = 0

    with pytest.raises(ResourceQuotaExceeded, match="max_descendants_unsupported"):
        RuntimeBudget(max_descendants=HostileNumber())

    assert HostileNumber.touched == 0


def test_stage1977_runtime_budget_env_reason_preserves_exact_builtin_text() -> None:
    name = "UMIGE_MAX_DESCENDANTS"
    previous = os.environ.get(name)
    os.environ[name] = "2.5"
    try:
        with pytest.raises(ResourceQuotaExceeded, match="umige_max_descendants_unsupported"):
            RuntimeBudget.from_env()
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


def test_stage1977_resource_runtime_sources_close_current_no_hook_rows() -> None:
    resource_paths = read_python_file(Path("Virus_Scan/runtime/resource_paths.py"))
    resource_quotas = read_python_file(Path("Virus_Scan/runtime/resource_quotas.py"))

    for filename, source in (
        ("resource_paths.py", resource_paths),
        ("resource_quotas.py", resource_quotas),
    ):
        tree = ast.parse(source, filename=filename)
        assert [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []

    assert "missing_reason=f" not in resource_paths
    assert "unsupported_reason=f" not in resource_paths
    assert "raise ValueError(reason or f" not in resource_paths
    assert "raise RuntimeError(f" not in resource_paths
    assert "except NameError" not in resource_paths
    assert "marker = __compiled__" in resource_paths
    assert "return _false_bool()" in resource_paths

    assert "def _quota_exception_reason(exc: BaseException | str, *, default:" not in resource_quotas
    assert "target = safe_zip_target(tmp_dir" not in resource_quotas
    assert "f\"{field_name}_unsupported\"" not in resource_quotas
    assert "f\"{name.lower()}_unsupported\"" not in resource_quotas
