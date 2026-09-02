"""Canonical packaged Node runtime ownership for TypeScript parsing.

The JavaScript/TypeScript frontend may execute only the manifest-selected Node
binary shipped inside the application distribution. Host PATH lookup,
environment overrides, operating-system package discovery, and alternate
runtime fallbacks are intentionally absent.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PosixPath, PurePosixPath, WindowsPath

from Virus_Scan.contracts.runtime_platform_identity import runtime_platform_identity
from Virus_Scan.runtime.api import path_contains_filesystem_alias

TYPESCRIPT_NODE_RUNTIME_MANIFEST_SCHEMA_VERSION = "typescript_node_runtime_manifest_v1"
TYPESCRIPT_NODE_RUNTIME_MANIFEST_SHA256 = (
    "feb5a9d63be27488e268670ffb8dadff1b3fc4e8a6dfc7c8330e801c15c1f591"
)
_NODE_RUNTIME_MANIFEST_NAME = "node_runtime_manifest.json"
_HEX = frozenset("0123456789abcdef")
_MANIFEST_FIELDS = frozenset({
    "license_relative_path",
    "license_sha256",
    "node_version",
    "release_shasums_relative_path",
    "release_shasums_sha256",
    "schema_version",
    "targets",
})
_TARGET_FIELDS = frozenset({
    "abi",
    "architecture",
    "archive_name",
    "archive_sha256",
    "platform",
    "relative_path",
    "sha256",
    "size",
})


@dataclass(frozen=True, slots=True)
class PackagedNodeRuntimeState:
    available: bool
    reason: str
    executable_path: str
    node_version: str
    target_platform: str
    target_architecture: str
    target_abi: str
    executable_sha256: str
    executable_size: int
    manifest_path: str
    manifest_sha256: str
    runtime_identity_digest: str


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8", "strict")
    return hashlib.sha256(encoded).hexdigest()


def _owned_text(value: object, reason: str, *, maximum: int = 512) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value)
    if not text or len(text) > maximum:
        raise ValueError(reason)
    return text


def _owned_sha256(value: object, reason: str) -> str:
    text = _owned_text(value, reason, maximum=64).lower()
    if len(text) != 64 or any(character not in _HEX for character in text):
        raise ValueError(reason)
    return text


def _owned_size(value: object, reason: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(reason)
    return value


def _safe_relative_path(value: object, reason: str) -> str:
    text = _owned_text(value, reason, maximum=512).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(reason)
    return path.as_posix()


def _host_target() -> tuple[str, str, str]:
    identity = runtime_platform_identity()
    target_abi = {"linux": "glibc", "windows": "msvc"}.get(
        identity.operating_system,
        "unsupported",
    )
    return identity.operating_system, identity.architecture, target_abi


def _unavailable(
    reason: str,
    *,
    manifest_path: Path,
    platform_name: str,
    architecture: str,
    abi: str,
    version: str = "",
    executable_sha256: str = "",
    executable_size: int = 0,
) -> PackagedNodeRuntimeState:
    return PackagedNodeRuntimeState(
        available=False,
        reason=reason[:512],
        executable_path="",
        node_version=version,
        target_platform=platform_name,
        target_architecture=architecture,
        target_abi=abi,
        executable_sha256=executable_sha256,
        executable_size=executable_size,
        manifest_path=str(manifest_path),
        manifest_sha256=TYPESCRIPT_NODE_RUNTIME_MANIFEST_SHA256,
        runtime_identity_digest="",
    )


def packaged_typescript_node_runtime_state(
    resource_root: Path,
) -> PackagedNodeRuntimeState:
    """Resolve and verify the sole packaged Node runtime for this host."""
    if type(resource_root) not in (Path, PosixPath, WindowsPath):
        raise TypeError("typescript_node_runtime_resource_root_invalid")
    root = resource_root.absolute()
    manifest_path = root / _NODE_RUNTIME_MANIFEST_NAME
    platform_name, architecture, abi = _host_target()
    if path_contains_filesystem_alias(manifest_path) or not manifest_path.is_file():
        return _unavailable(
            "typescript_node_runtime_manifest_missing",
            manifest_path=manifest_path,
            platform_name=platform_name,
            architecture=architecture,
            abi=abi,
        )
    version = ""
    expected_sha = ""
    expected_size = 0
    try:
        if _file_digest(manifest_path) != TYPESCRIPT_NODE_RUNTIME_MANIFEST_SHA256:
            raise ValueError("typescript_node_runtime_manifest_integrity_failed")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if type(manifest) is not dict or set(manifest) != _MANIFEST_FIELDS:
            raise ValueError("typescript_node_runtime_manifest_invalid")
        schema = _owned_text(
            manifest["schema_version"],
            "typescript_node_runtime_manifest_schema_invalid",
        )
        if schema != TYPESCRIPT_NODE_RUNTIME_MANIFEST_SCHEMA_VERSION:
            raise ValueError("typescript_node_runtime_manifest_schema_invalid")
        version = _owned_text(
            manifest["node_version"],
            "typescript_node_runtime_version_invalid",
        )
        license_relative = _safe_relative_path(
            manifest["license_relative_path"],
            "typescript_node_runtime_license_path_invalid",
        )
        license_sha = _owned_sha256(
            manifest["license_sha256"],
            "typescript_node_runtime_license_digest_invalid",
        )
        shasums_relative = _safe_relative_path(
            manifest["release_shasums_relative_path"],
            "typescript_node_runtime_shasums_path_invalid",
        )
        shasums_sha = _owned_sha256(
            manifest["release_shasums_sha256"],
            "typescript_node_runtime_shasums_digest_invalid",
        )
        targets = manifest["targets"]
        if type(targets) is not list or not targets or len(targets) > 32:
            raise ValueError("typescript_node_runtime_targets_invalid")
        selected: dict[str, object] | None = None
        seen: set[tuple[str, str, str]] = set()
        normalized_targets: list[dict[str, object]] = []
        for value in targets:
            if type(value) is not dict or set(value) != _TARGET_FIELDS:
                raise ValueError("typescript_node_runtime_target_invalid")
            target = {
                "abi": _owned_text(
                    value["abi"], "typescript_node_runtime_target_abi_invalid"
                ),
                "architecture": _owned_text(
                    value["architecture"],
                    "typescript_node_runtime_target_architecture_invalid",
                ),
                "archive_name": _owned_text(
                    value["archive_name"],
                    "typescript_node_runtime_archive_name_invalid",
                ),
                "archive_sha256": _owned_sha256(
                    value["archive_sha256"],
                    "typescript_node_runtime_archive_digest_invalid",
                ),
                "platform": _owned_text(
                    value["platform"],
                    "typescript_node_runtime_target_platform_invalid",
                ),
                "relative_path": _safe_relative_path(
                    value["relative_path"],
                    "typescript_node_runtime_path_invalid",
                ),
                "sha256": _owned_sha256(
                    value["sha256"], "typescript_node_runtime_digest_invalid"
                ),
                "size": _owned_size(
                    value["size"], "typescript_node_runtime_size_invalid"
                ),
            }
            key = (
                str(target["platform"]),
                str(target["architecture"]),
                str(target["abi"]),
            )
            if key in seen:
                raise ValueError("typescript_node_runtime_target_duplicate")
            seen.add(key)
            normalized_targets.append(target)
            if key == (platform_name, architecture, abi):
                selected = target
        for relative, expected, reason in (
            (
                license_relative,
                license_sha,
                "typescript_node_runtime_license_integrity_failed",
            ),
            (
                shasums_relative,
                shasums_sha,
                "typescript_node_runtime_shasums_integrity_failed",
            ),
        ):
            candidate = root / relative
            if path_contains_filesystem_alias(candidate):
                raise ValueError(reason)
            path = candidate.resolve()
            path.relative_to(root)
            if not path.is_file() or _file_digest(path) != expected:
                raise ValueError(reason)
        if selected is None:
            return _unavailable(
                "typescript_node_runtime_target_unavailable",
                manifest_path=manifest_path,
                platform_name=platform_name,
                architecture=architecture,
                abi=abi,
                version=version,
            )
        expected_sha = str(selected["sha256"])
        expected_size = int(selected["size"])
        candidate = root / str(selected["relative_path"])
        if path_contains_filesystem_alias(candidate):
            raise ValueError("typescript_node_runtime_binary_substituted")
        executable_path = candidate.resolve()
        executable_path.relative_to(root)
        if not executable_path.is_file():
            return _unavailable(
                "typescript_node_runtime_binary_missing",
                manifest_path=manifest_path,
                platform_name=platform_name,
                architecture=architecture,
                abi=abi,
                version=version,
                executable_sha256=expected_sha,
                executable_size=expected_size,
            )
        actual_size = executable_path.stat().st_size
        if actual_size != expected_size:
            raise ValueError("typescript_node_runtime_binary_size_mismatch")
        if _file_digest(executable_path) != expected_sha:
            raise ValueError("typescript_node_runtime_binary_integrity_failed")
        if platform_name != "windows" and not os.access(executable_path, os.X_OK):
            raise ValueError("typescript_node_runtime_binary_not_executable")
        runtime_identity = _canonical_digest({
            "manifest_sha256": TYPESCRIPT_NODE_RUNTIME_MANIFEST_SHA256,
            "node_version": version,
            "selected_target": selected,
            "targets": normalized_targets,
        })
        return PackagedNodeRuntimeState(
            available=True,
            reason="",
            executable_path=str(executable_path),
            node_version=version,
            target_platform=platform_name,
            target_architecture=architecture,
            target_abi=abi,
            executable_sha256=expected_sha,
            executable_size=expected_size,
            manifest_path=str(manifest_path),
            manifest_sha256=TYPESCRIPT_NODE_RUNTIME_MANIFEST_SHA256,
            runtime_identity_digest=runtime_identity,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        reason = str(exc) or "typescript_node_runtime_manifest_invalid"
        return _unavailable(
            reason,
            manifest_path=manifest_path,
            platform_name=platform_name,
            architecture=architecture,
            abi=abi,
            version=version,
            executable_sha256=expected_sha,
            executable_size=expected_size,
        )


__all__ = (
    "PackagedNodeRuntimeState",
    "TYPESCRIPT_NODE_RUNTIME_MANIFEST_SCHEMA_VERSION",
    "TYPESCRIPT_NODE_RUNTIME_MANIFEST_SHA256",
    "packaged_typescript_node_runtime_state",
)
