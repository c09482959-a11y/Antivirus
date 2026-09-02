"""Finalize immutable packaged runtimes after Nuitka dependency processing.

Nuitka correctly discovers native dependencies but rewrites ELF RPATH metadata
when copying DLL/executable entries. Capstone and Node are integrity-pinned
artifacts whose runtime contracts require the exact repository bytes. This
module is the sole build-time owner that atomically restores those exact bytes
at their canonical distribution-relative paths and verifies the result.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PosixPath, WindowsPath
import stat
import tempfile

from Virus_Scan.contracts.runtime_platform_identity import runtime_platform_identity
from Virus_Scan.runtime.api import (
    durable_replace_regular_file,
    flush_open_writable_file,
    path_contains_filesystem_alias,
)

_CAPSTONE_MANIFEST_RELATIVE = Path("packaged_capstone_5_0_9/dependency_manifest.json")
_NODE_RESOURCE_RELATIVE = Path(
    "Virus_Scan/scanners/static_program_analysis/typescript_parser_resource"
)
_NODE_MANIFEST_NAME = "node_runtime_manifest.json"
_LEGACY_CAPSTONE_RELATIVES = (
    Path("capstone/lib/libcapstone.so"),
    Path("capstone/lib/capstone.dll"),
)
_LEGACY_NODE_ROOT = Path("typescript_parser_resource/node_runtime")
_HEX = frozenset("0123456789abcdef")
_COPY_CHUNK_BYTES = 1024 * 1024


class PackagedRuntimeFinalizationError(RuntimeError):
    """The standalone distribution cannot satisfy immutable runtime identity."""


@dataclass(frozen=True, slots=True)
class PackagedRuntimeReceipt:
    """Verified final distribution identity for one immutable runtime file."""

    runtime_id: str
    relative_path: str
    sha256: str
    size: int
    executable: bool


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(_COPY_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _exact_text(value: object, reason: str) -> str:
    if type(value) is not str or not value:
        raise PackagedRuntimeFinalizationError(reason)
    return str.__str__(value)


def _exact_size(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool or value <= 0:
        raise PackagedRuntimeFinalizationError(reason)
    return int(value)


def _exact_sha256(value: object, reason: str) -> str:
    text = _exact_text(value, reason).lower()
    if len(text) != 64 or any(character not in _HEX for character in text):
        raise PackagedRuntimeFinalizationError(reason)
    return text


def _safe_relative(value: object, reason: str) -> Path:
    path = Path(_exact_text(value, reason))
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise PackagedRuntimeFinalizationError(reason)
    return path


def _regular_source(path: Path, reason: str) -> None:
    if path_contains_filesystem_alias(path) or not path.is_file():
        raise PackagedRuntimeFinalizationError(reason)


def _validate_source(
    path: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    reason_prefix: str,
) -> None:
    _regular_source(path, f"{reason_prefix}_source_unavailable")
    if path.stat().st_size != expected_size:
        raise PackagedRuntimeFinalizationError(f"{reason_prefix}_source_size_mismatch")
    if _sha256(path) != expected_sha256:
        raise PackagedRuntimeFinalizationError(f"{reason_prefix}_source_sha256_mismatch")


def _host_target() -> tuple[str, str]:
    identity = runtime_platform_identity()
    if identity.operating_system not in {"linux", "windows"}:
        raise PackagedRuntimeFinalizationError("runtime_packaging_platform_unsupported")
    if identity.architecture != "x86_64":
        raise PackagedRuntimeFinalizationError("runtime_packaging_architecture_unsupported")
    return identity.operating_system, identity.architecture


def _platform_requires_posix_execute_mode(platform_name: str) -> bool:
    if platform_name == "linux":
        return True
    if platform_name == "windows":
        return False
    raise PackagedRuntimeFinalizationError("runtime_packaging_platform_unsupported")


def _validate_capstone_target_for_platform(
    target: object,
    *,
    platform_name: str,
    architecture: str,
) -> None:
    if type(target) is not dict:
        raise PackagedRuntimeFinalizationError("capstone_packaging_target_manifest_invalid")
    if target.get("operating_system") != platform_name:
        raise PackagedRuntimeFinalizationError("capstone_packaging_target_unavailable")
    if target.get("architecture") != architecture:
        raise PackagedRuntimeFinalizationError("capstone_packaging_target_unavailable")


def _atomic_exact_copy(
    source: Path,
    target: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    executable: bool,
    reason_prefix: str,
    platform_name: str,
) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    source_mode = stat.S_IMODE(source.stat().st_mode)
    require_execute_mode = _platform_requires_posix_execute_mode(platform_name)
    if executable and require_execute_mode and source_mode & stat.S_IXUSR == 0:
        raise PackagedRuntimeFinalizationError(f"{reason_prefix}_source_not_executable")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".exact-runtime.tmp",
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output, source.open("rb") as input_stream:
            while True:
                chunk = input_stream.read(_COPY_CHUNK_BYTES)
                if not chunk:
                    break
                output.write(chunk)
            output.flush()
            flush_open_writable_file(output.fileno())
        os.chmod(temporary, source_mode)
        if temporary.stat().st_size != expected_size or _sha256(temporary) != expected_sha256:
            raise PackagedRuntimeFinalizationError(f"{reason_prefix}_temporary_integrity_failed")
        durable_replace_regular_file(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    if path_contains_filesystem_alias(target) or not target.is_file():
        raise PackagedRuntimeFinalizationError(f"{reason_prefix}_target_unavailable")
    if target.stat().st_size != expected_size or _sha256(target) != expected_sha256:
        raise PackagedRuntimeFinalizationError(f"{reason_prefix}_target_integrity_failed")
    if (
        executable
        and require_execute_mode
        and stat.S_IMODE(target.stat().st_mode) & stat.S_IXUSR == 0
    ):
        raise PackagedRuntimeFinalizationError(f"{reason_prefix}_target_not_executable")


def _load_mapping(path: Path, reason: str) -> dict[str, object]:
    _regular_source(path, reason)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackagedRuntimeFinalizationError(reason) from exc
    if type(value) is not dict:
        raise PackagedRuntimeFinalizationError(reason)
    return value


def _capstone_specs(
    repository_root: Path,
    *,
    platform_name: str | None = None,
    architecture: str | None = None,
) -> tuple[tuple[str, Path, Path, int, str, bool], ...]:
    manifest = _load_mapping(
        repository_root / _CAPSTONE_MANIFEST_RELATIVE,
        "capstone_packaging_manifest_invalid",
    )
    binding = manifest.get("binding")
    targets = manifest.get("targets")
    if platform_name is None or architecture is None:
        host_platform, host_architecture = _host_target()
    else:
        host_platform, host_architecture = platform_name, architecture
    selected_platform = platform_name or host_platform
    selected_architecture = architecture or host_architecture
    if type(binding) is not dict:
        raise PackagedRuntimeFinalizationError("capstone_packaging_binding_manifest_invalid")
    if type(targets) is not list or not targets:
        raise PackagedRuntimeFinalizationError("capstone_packaging_targets_manifest_invalid")

    binding_relative = _safe_relative(
        binding.get("path"),
        "capstone_packaging_binding_path_invalid",
    )
    if binding_relative != Path("packaged_capstone_5_0_9/capstone/__init__.py"):
        raise PackagedRuntimeFinalizationError("capstone_packaging_binding_path_unpinned")
    binding_size = _exact_size(
        binding.get("size"),
        "capstone_packaging_binding_size_invalid",
    )
    binding_digest = _exact_sha256(
        binding.get("sha256"),
        "capstone_packaging_binding_sha256_invalid",
    )

    selected_core: dict[str, object] | None = None
    for record in targets:
        if type(record) is not dict or set(record) != {"native_core", "provenance", "target"}:
            raise PackagedRuntimeFinalizationError("capstone_packaging_target_record_invalid")
        target = record.get("target")
        if type(target) is not dict:
            raise PackagedRuntimeFinalizationError("capstone_packaging_target_manifest_invalid")
        target_key = (target.get("operating_system"), target.get("architecture"))
        if target_key not in {("linux", "x86_64"), ("windows", "x86_64")}:
            raise PackagedRuntimeFinalizationError("capstone_packaging_target_manifest_invalid")
        if target_key == (selected_platform, selected_architecture):
            _validate_capstone_target_for_platform(
                target,
                platform_name=selected_platform,
                architecture=selected_architecture,
            )
            if selected_core is not None:
                raise PackagedRuntimeFinalizationError("capstone_packaging_target_duplicate")
            core = record.get("native_core")
            if type(core) is not dict:
                raise PackagedRuntimeFinalizationError("capstone_packaging_core_manifest_invalid")
            selected_core = core
    if selected_core is None:
        raise PackagedRuntimeFinalizationError("capstone_packaging_target_unavailable")

    core_relative = _safe_relative(
        selected_core.get("path"),
        "capstone_packaging_core_path_invalid",
    )
    expected_core = (
        Path("packaged_capstone_5_0_9/capstone/lib/libcapstone.so")
        if selected_platform == "linux"
        else Path("packaged_capstone_5_0_9/capstone/lib/capstone.dll")
    )
    if core_relative != expected_core:
        raise PackagedRuntimeFinalizationError("capstone_packaging_core_path_unpinned")
    core_size = _exact_size(
        selected_core.get("size"),
        "capstone_packaging_core_size_invalid",
    )
    core_digest = _exact_sha256(
        selected_core.get("sha256"),
        "capstone_packaging_core_sha256_invalid",
    )
    return (
        (
            "capstone-binding-5.0.9",
            repository_root / binding_relative,
            binding_relative,
            binding_size,
            binding_digest,
            False,
        ),
        (
            f"capstone-core-5.0.9-{selected_platform}-{selected_architecture}",
            repository_root / core_relative,
            core_relative,
            core_size,
            core_digest,
            False,
        ),
    )


def _capstone_core_paths(repository_root: Path) -> tuple[Path, ...]:
    manifest = _load_mapping(
        repository_root / _CAPSTONE_MANIFEST_RELATIVE,
        "capstone_packaging_manifest_invalid",
    )
    targets = manifest.get("targets")
    if type(targets) is not list or not targets:
        raise PackagedRuntimeFinalizationError("capstone_packaging_targets_manifest_invalid")
    paths: list[Path] = []
    for record in targets:
        if type(record) is not dict:
            raise PackagedRuntimeFinalizationError("capstone_packaging_target_record_invalid")
        core = record.get("native_core")
        if type(core) is not dict:
            raise PackagedRuntimeFinalizationError("capstone_packaging_core_manifest_invalid")
        relative = _safe_relative(core.get("path"), "capstone_packaging_core_path_invalid")
        if relative in paths:
            raise PackagedRuntimeFinalizationError("capstone_packaging_core_path_duplicate")
        paths.append(relative)
    return tuple(paths)


def _node_spec(
    repository_root: Path,
    *,
    target_key: tuple[str, str, str] | None = None,
) -> tuple[Path, Path, int, str]:
    resource_root = repository_root / _NODE_RESOURCE_RELATIVE
    manifest = _load_mapping(
        resource_root / _NODE_MANIFEST_NAME,
        "node_packaging_manifest_invalid",
    )
    targets = manifest.get("targets")
    if type(targets) is not list or not targets:
        raise PackagedRuntimeFinalizationError("node_packaging_targets_invalid")
    if target_key is None:
        platform_name, architecture = _host_target()
        expected_key = (
            platform_name,
            architecture,
            "glibc" if platform_name == "linux" else "msvc",
        )
    else:
        expected_key = target_key
    selected: dict[str, object] | None = None
    for value in targets:
        if type(value) is not dict:
            raise PackagedRuntimeFinalizationError("node_packaging_target_invalid")
        key = (value.get("platform"), value.get("architecture"), value.get("abi"))
        if key == expected_key:
            if selected is not None:
                raise PackagedRuntimeFinalizationError("node_packaging_target_duplicate")
            selected = value
    if selected is None:
        raise PackagedRuntimeFinalizationError("node_packaging_target_unavailable")
    resource_relative = _safe_relative(
        selected.get("relative_path"),
        "node_packaging_runtime_path_invalid",
    )
    relative = _NODE_RESOURCE_RELATIVE / resource_relative
    expected_suffix = (
        Path("node_runtime/linux-x86_64/node")
        if expected_key[0] == "linux"
        else Path("node_runtime/windows-x86_64/node.exe")
    )
    if resource_relative != expected_suffix:
        raise PackagedRuntimeFinalizationError("node_packaging_runtime_path_unpinned")
    size = _exact_size(selected.get("size"), "node_packaging_runtime_size_invalid")
    digest = _exact_sha256(selected.get("sha256"), "node_packaging_runtime_sha256_invalid")
    return resource_root / resource_relative, relative, size, digest


def finalize_exact_packaged_runtimes(
    repository_root: Path,
    distribution_root: Path,
) -> tuple[PackagedRuntimeReceipt, ...]:
    """Atomically restore and verify the exact manifest-pinned runtime bytes."""
    allowed_path_types = (Path, PosixPath, WindowsPath)
    if type(repository_root) not in allowed_path_types or type(distribution_root) not in allowed_path_types:
        raise TypeError("nuitka_runtime_finalizer_path_type_required")
    repository = repository_root.absolute()
    distribution = distribution_root.absolute()
    if path_contains_filesystem_alias(repository) or not repository.is_dir():
        raise PackagedRuntimeFinalizationError("nuitka_repository_root_invalid")
    if path_contains_filesystem_alias(distribution) or not distribution.is_dir():
        raise PackagedRuntimeFinalizationError("nuitka_distribution_root_invalid")

    legacy_capstone = tuple(distribution / path for path in _LEGACY_CAPSTONE_RELATIVES)
    legacy_node = distribution / _LEGACY_NODE_ROOT
    if any(path.exists() for path in legacy_capstone) or legacy_node.exists():
        raise PackagedRuntimeFinalizationError("nuitka_noncanonical_runtime_path_present")

    platform_name, architecture = _host_target()
    capstone_specs = _capstone_specs(
        repository,
        platform_name=platform_name,
        architecture=architecture,
    )
    selected_core_relative = capstone_specs[1][2]
    for relative in _capstone_core_paths(repository):
        if relative != selected_core_relative and (distribution / relative).exists():
            raise PackagedRuntimeFinalizationError("nuitka_unselected_runtime_path_present")
    node_key = (
        platform_name,
        architecture,
        "glibc" if platform_name == "linux" else "msvc",
    )
    specifications = (
        *capstone_specs,
        (
            f"node-22.16.0-{platform_name}-{architecture}",
            *_node_spec(repository, target_key=node_key),
            True,
        ),
    )
    receipts: list[PackagedRuntimeReceipt] = []
    for runtime_id, source, relative, size, digest, executable in specifications:
        _validate_source(
            source,
            expected_size=size,
            expected_sha256=digest,
            reason_prefix=runtime_id,
        )
        target = distribution / relative
        try:
            target.resolve().relative_to(distribution)
        except ValueError as exc:
            raise PackagedRuntimeFinalizationError("nuitka_runtime_target_escape") from exc
        _atomic_exact_copy(
            source,
            target,
            expected_size=size,
            expected_sha256=digest,
            executable=executable,
            reason_prefix=runtime_id,
            platform_name=platform_name,
        )
        receipts.append(
            PackagedRuntimeReceipt(
                runtime_id=runtime_id,
                relative_path=relative.as_posix(),
                sha256=digest,
                size=size,
                executable=executable,
            )
        )
    return tuple(receipts)
