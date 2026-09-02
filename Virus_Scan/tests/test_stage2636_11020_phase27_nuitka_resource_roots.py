"""Phase 27 canonical standalone resource-root packaging regressions."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil

import pytest

from Virus_Scan.runtime.resource_paths import (
    RESOURCE_CLASSIFICATION_PACKAGE, RESOURCE_CLASSIFICATION_RUNTIME_CONTROL,
    resource_root_snapshot_from_program_root,
)
from tools.nuitka_packaging.package_resource_projection import (
    PackageResourceProjectionError,
    canonical_package_resource_records,
    verify_standalone_package_resources,
)


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_phase27_package_resource_names_are_owned_by_resource_contract() -> None:
    root = _root()
    snapshot = resource_root_snapshot_from_program_root(root)
    records = canonical_package_resource_records(root)
    assert records
    expected = {
        (root_name, Path(source_path).name)
        for root_name, source_path in snapshot.standalone_package_resources()
    }
    observed: set[tuple[str, str]] = set()
    for record in records:
        source = Path(record.source_path)
        assert snapshot.classify(source) in {RESOURCE_CLASSIFICATION_PACKAGE, RESOURCE_CLASSIFICATION_RUNTIME_CONTROL}
        assert record.size == source.stat().st_size
        assert record.sha256 == _sha256(source)
        observed.add((record.root_name, source.name))
    assert observed == expected


def test_phase27_standalone_resource_projection_excludes_runtime_state(tmp_path: Path) -> None:
    root = _root()
    distribution = tmp_path / "application.dist"
    distribution.mkdir()
    records = canonical_package_resource_records(root)
    for record in records:
        target = distribution / record.relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(record.source_path, target)
    verified = verify_standalone_package_resources(root, distribution)
    assert verified == records
    assert not (distribution / "Mitre/.umige-mitre.lock").exists()
    assert not (distribution / "Mitre/mitre_state.json").exists()
    assert not (distribution / "Mitre/enterprise-attack-index.json").exists()
    assert not (distribution / "Scan Logs/.staging").exists()


def test_phase27_standalone_resource_projection_rejects_missing_package_file(tmp_path: Path) -> None:
    root = _root()
    distribution = tmp_path / "application.dist"
    distribution.mkdir()
    records = canonical_package_resource_records(root)
    for record in records:
        target = distribution / record.relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(record.source_path, target)
    (distribution / records[0].relative_path).unlink()
    with pytest.raises(PackageResourceProjectionError, match="target_unavailable"):
        verify_standalone_package_resources(root, distribution)


def test_phase27_standalone_resource_projection_rejects_runtime_state(tmp_path: Path) -> None:
    root = _root()
    distribution = tmp_path / "application.dist"
    distribution.mkdir()
    for record in canonical_package_resource_records(root):
        target = distribution / record.relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(record.source_path, target)
    leaked = distribution / "Yara/yara.cache/groups/compiled-deadbeef.yarc"
    leaked.parent.mkdir(parents=True, exist_ok=True)
    leaked.write_bytes(b"runtime")
    with pytest.raises(PackageResourceProjectionError, match="runtime_state_present"):
        verify_standalone_package_resources(root, distribution)


def test_phase27_nuitka_plugin_projects_and_verifies_resource_roots_once() -> None:
    source = (_root() / "tools/nuitka_packaging/exact_runtime_plugin.py").read_text(encoding="utf-8")
    assert source.count("canonical_package_resource_records(") == 1
    assert source.count("verify_standalone_package_resources(") == 1
    assert "Virus_Scan.runtime.resource_paths" in source


def test_phase27_build_projection_has_no_independent_root_literal_owner() -> None:
    source = (_root() / "tools/nuitka_packaging/package_resource_projection.py").read_text(encoding="utf-8")
    for literal in ("\"Yara\"", "\"Mitre\"", "\"VirusTotal\"", "\"Scan Logs\""):
        assert literal not in source
