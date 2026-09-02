"""Phase 23 exact-byte standalone runtime finalization regressions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat

import pytest

from Virus_Scan.contracts.runtime_platform_identity import runtime_platform_identity
from tools.nuitka_packaging.exact_runtime_finalizer import (
    PackagedRuntimeFinalizationError,
    _capstone_specs,
    _node_spec,
    _platform_requires_posix_execute_mode,
    finalize_exact_packaged_runtimes,
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _fixture_repository(
    root: Path,
) -> tuple[Path, bytes, bytes, bytes, bytes, bytes]:
    binding = b"# exact packaged Capstone binding\n"
    linux_capstone = b"exact-linux-capstone-core"
    windows_capstone = b"exact-windows-capstone-core"
    linux_node = b"#!/bin/sh\nexit 0\n"
    windows_node = b"MZexact-windows-node"
    binding_path = root / "packaged_capstone_5_0_9/capstone/__init__.py"
    linux_capstone_path = root / "packaged_capstone_5_0_9/capstone/lib/libcapstone.so"
    windows_capstone_path = root / "packaged_capstone_5_0_9/capstone/lib/capstone.dll"
    node_root = (
        root
        / "Virus_Scan/scanners/static_program_analysis/typescript_parser_resource"
    )
    linux_node_path = node_root / "node_runtime/linux-x86_64/node"
    windows_node_path = node_root / "node_runtime/windows-x86_64/node.exe"
    for path in (
        binding_path,
        linux_capstone_path,
        windows_capstone_path,
        linux_node_path,
        windows_node_path,
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
    binding_path.write_bytes(binding)
    linux_capstone_path.write_bytes(linux_capstone)
    windows_capstone_path.write_bytes(windows_capstone)
    linux_node_path.write_bytes(linux_node)
    windows_node_path.write_bytes(windows_node)
    linux_node_path.chmod(0o755)
    capstone_manifest = {
        "binding": {
            "path": "packaged_capstone_5_0_9/capstone/__init__.py",
            "sha256": _sha256(binding),
            "size": len(binding),
        },
        "targets": [
            {
                "native_core": {
                    "path": "packaged_capstone_5_0_9/capstone/lib/libcapstone.so",
                    "sha256": _sha256(linux_capstone),
                    "size": len(linux_capstone),
                },
                "provenance": {},
                "target": {
                    "architecture": "x86_64",
                    "operating_system": "linux",
                },
            },
            {
                "native_core": {
                    "path": "packaged_capstone_5_0_9/capstone/lib/capstone.dll",
                    "sha256": _sha256(windows_capstone),
                    "size": len(windows_capstone),
                },
                "provenance": {},
                "target": {
                    "architecture": "x86_64",
                    "operating_system": "windows",
                },
            },
        ],
    }
    (root / "packaged_capstone_5_0_9/dependency_manifest.json").write_text(
        json.dumps(capstone_manifest, sort_keys=True),
        encoding="utf-8",
    )
    node_manifest = {
        "targets": [
            {
                "abi": "glibc",
                "architecture": "x86_64",
                "platform": "linux",
                "relative_path": "node_runtime/linux-x86_64/node",
                "sha256": _sha256(linux_node),
                "size": len(linux_node),
            },
            {
                "abi": "msvc",
                "architecture": "x86_64",
                "platform": "windows",
                "relative_path": "node_runtime/windows-x86_64/node.exe",
                "sha256": _sha256(windows_node),
                "size": len(windows_node),
            },
        ]
    }
    (node_root / "node_runtime_manifest.json").write_text(
        json.dumps(node_manifest, sort_keys=True),
        encoding="utf-8",
    )
    return (
        root,
        binding,
        linux_capstone,
        windows_capstone,
        linux_node,
        windows_node,
    )


def test_phase23_exact_runtime_finalizer_restores_manifest_bytes(
    tmp_path: Path,
) -> None:
    repository, binding, linux_capstone, windows_capstone, linux_node, windows_node = (
        _fixture_repository(tmp_path / "repository")
    )
    platform_identity = runtime_platform_identity()
    if platform_identity.operating_system == "linux":
        capstone_relative = Path(
            "packaged_capstone_5_0_9/capstone/lib/libcapstone.so"
        )
        node_relative = Path(
            "Virus_Scan/scanners/static_program_analysis/typescript_parser_resource/"
            "node_runtime/linux-x86_64/node"
        )
        expected_capstone = linux_capstone
        expected_node = linux_node
        opposite_capstone = Path(
            "packaged_capstone_5_0_9/capstone/lib/capstone.dll"
        )
    else:
        assert platform_identity.operating_system == "windows"
        capstone_relative = Path(
            "packaged_capstone_5_0_9/capstone/lib/capstone.dll"
        )
        node_relative = Path(
            "Virus_Scan/scanners/static_program_analysis/typescript_parser_resource/"
            "node_runtime/windows-x86_64/node.exe"
        )
        expected_capstone = windows_capstone
        expected_node = windows_node
        opposite_capstone = Path(
            "packaged_capstone_5_0_9/capstone/lib/libcapstone.so"
        )
    distribution = tmp_path / "application.dist"
    binding_target = distribution / "packaged_capstone_5_0_9/capstone/__init__.py"
    capstone_target = distribution / capstone_relative
    node_target = distribution / node_relative
    for path in (binding_target, capstone_target, node_target):
        path.parent.mkdir(parents=True, exist_ok=True)
    binding_target.write_bytes(b"nuitka-missing-or-mutated-binding")
    capstone_target.write_bytes(b"nuitka-mutated-capstone")
    node_target.write_bytes(b"nuitka-mutated-node")

    receipts = finalize_exact_packaged_runtimes(repository, distribution)

    assert tuple(receipt.runtime_id for receipt in receipts) == (
        "capstone-binding-5.0.9",
        "capstone-core-5.0.9-" + platform_identity.operating_system + "-x86_64",
        "node-22.16.0-" + platform_identity.operating_system + "-x86_64",
    )
    assert binding_target.read_bytes() == binding
    assert capstone_target.read_bytes() == expected_capstone
    assert node_target.read_bytes() == expected_node
    if platform_identity.operating_system == "linux":
        assert stat.S_IMODE(node_target.stat().st_mode) & stat.S_IXUSR
    assert not (distribution / opposite_capstone).exists()
    assert not (distribution / "capstone/lib/libcapstone.so").exists()
    assert not (distribution / "capstone/lib/capstone.dll").exists()
    assert not (distribution / "typescript_parser_resource/node_runtime").exists()


def test_phase23_exact_runtime_finalizer_rejects_noncanonical_duplicate(
    tmp_path: Path,
) -> None:
    repository, *_rest = _fixture_repository(tmp_path / "repository")
    distribution = tmp_path / "application.dist"
    legacy = distribution / "capstone/lib/libcapstone.so"
    legacy.parent.mkdir(parents=True)
    legacy.write_bytes(b"duplicate")

    with pytest.raises(
        PackagedRuntimeFinalizationError,
        match="nuitka_noncanonical_runtime_path_present",
    ):
        finalize_exact_packaged_runtimes(repository, distribution)


def test_phase27_exact_runtime_finalizer_rejects_unselected_platform_core(
    tmp_path: Path,
) -> None:
    repository, *_rest = _fixture_repository(tmp_path / "repository")
    distribution = tmp_path / "application.dist"
    platform_identity = runtime_platform_identity()
    unselected_relative = (
        "packaged_capstone_5_0_9/capstone/lib/capstone.dll"
        if platform_identity.operating_system == "linux"
        else "packaged_capstone_5_0_9/capstone/lib/libcapstone.so"
    )
    unselected = distribution / unselected_relative
    unselected.parent.mkdir(parents=True)
    unselected.write_bytes(b"duplicate-unselected-core")

    with pytest.raises(
        PackagedRuntimeFinalizationError,
        match="nuitka_unselected_runtime_path_present",
    ):
        finalize_exact_packaged_runtimes(repository, distribution)


def test_phase27_windows_specs_select_only_windows_runtime_bytes(tmp_path: Path) -> None:
    repository, _binding, _linux_core, windows_core, _linux_node, windows_node = (
        _fixture_repository(tmp_path / "repository")
    )

    capstone_specs = _capstone_specs(
        repository,
        platform_name="windows",
        architecture="x86_64",
    )
    node_source, node_relative, node_size, node_digest = _node_spec(
        repository,
        target_key=("windows", "x86_64", "msvc"),
    )

    assert capstone_specs[1][0] == "capstone-core-5.0.9-windows-x86_64"
    assert capstone_specs[1][1].read_bytes() == windows_core
    assert capstone_specs[1][2] == Path(
        "packaged_capstone_5_0_9/capstone/lib/capstone.dll"
    )
    assert node_source.read_bytes() == windows_node
    assert node_relative.as_posix().endswith("node_runtime/windows-x86_64/node.exe")
    assert node_size == len(windows_node)
    assert node_digest == _sha256(windows_node)


def test_phase27_runtime_finalizer_uses_platform_native_execute_semantics() -> None:
    assert _platform_requires_posix_execute_mode("linux") is True
    assert _platform_requires_posix_execute_mode("windows") is False
