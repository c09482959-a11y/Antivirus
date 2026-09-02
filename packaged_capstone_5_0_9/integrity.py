"""Immutable repository-packaged Capstone dependency integrity owner."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct

from Virus_Scan.contracts.runtime_platform_identity import runtime_platform_identity
from Virus_Scan.runtime.api import path_contains_filesystem_alias

PACKAGED_CAPSTONE_MANIFEST_SCHEMA_VERSION = "packaged_capstone_dependency_manifest_v4"
PACKAGED_CAPSTONE_DEPENDENCY_IDENTITY = "6629fee516a2773e58520d995d18c555d376da974a62bb9a5e1619543800839d"
_PACKAGE_ROOT = Path(__file__).absolute().parent
_EXPECTED_BINDING_VERSION = "5.0.7"
_EXPECTED_DISTRIBUTION_VERSION = "5.0.9"
_EXPECTED_TARGETS = frozenset({("linux", "x86_64"), ("windows", "x86_64")})
_HEX = frozenset("0123456789abcdef")
_MANIFEST_KEYS = frozenset({
    "binding",
    "binding_version",
    "dependency_identity_sha256",
    "distribution_name",
    "distribution_version",
    "license",
    "native_core_version",
    "packaging",
    "schema_version",
    "targets",
})
_TARGET_RECORD_KEYS = frozenset({"native_core", "provenance", "target"})
_TARGET_KEYS = frozenset({
    "abi",
    "architecture",
    "endianness",
    "modes",
    "operating_system",
    "syntax",
})
_CORE_KEYS = frozenset({
    "binary_class",
    "binary_format",
    "exported_api",
    "filename",
    "machine",
    "path",
    "required_exports",
    "sha256",
    "size",
})
_PROVENANCE_KEYS = frozenset({
    "native_core_member",
    "package_index_identity",
    "wheel_filename",
    "wheel_sha256",
    "wheel_size",
    "wheel_tag",
})
_REQUIRED_EXPORTS = (
    "cs_close",
    "cs_disasm",
    "cs_free",
    "cs_open",
    "cs_option",
    "cs_version",
)


class PackagedCapstoneUnavailable(RuntimeError):
    """The pinned repository dependency does not satisfy its exact manifest."""


@dataclass(frozen=True, slots=True)
class PackagedCapstoneIdentity:
    """Validated immutable binding, core, platform, and API identity."""

    state: str
    reason: str
    identity_digest: str
    distribution_version: str
    binding_version: str
    binding_path: str
    binding_sha256: str
    native_core_version: tuple[int, int, int]
    native_core_path: str
    native_core_size: int
    native_core_sha256: str
    required_core_exports: tuple[str, ...]
    target_operating_system: str
    target_abi: str
    target_architecture: str
    target_endianness: str
    target_mode: str
    syntax: str

    @property
    def available(self) -> bool:
        return self.state == "available"

    def to_record(self) -> dict[str, object]:
        return {
            "binding_path": self.binding_path,
            "binding_sha256": self.binding_sha256,
            "binding_version": self.binding_version,
            "distribution_version": self.distribution_version,
            "identity_digest": self.identity_digest,
            "native_core_path": self.native_core_path,
            "native_core_sha256": self.native_core_sha256,
            "native_core_size": self.native_core_size,
            "native_core_version": list(self.native_core_version),
            "reason": self.reason,
            "required_core_exports": list(self.required_core_exports),
            "state": self.state,
            "syntax": self.syntax,
            "target_abi": self.target_abi,
            "target_architecture": self.target_architecture,
            "target_endianness": self.target_endianness,
            "target_mode": self.target_mode,
            "target_operating_system": self.target_operating_system,
        }


def _host_target() -> tuple[str, str, str]:
    identity = runtime_platform_identity()
    return identity.operating_system, identity.architecture, identity.abi


def unavailable_capstone_identity(
    reason: str,
    *,
    target_operating_system: str | None = None,
    target_abi: str | None = None,
    target_architecture: str | None = None,
) -> PackagedCapstoneIdentity:
    """Return the exact explicit unavailable dependency state."""
    host_os, host_arch, host_abi = _host_target()
    return PackagedCapstoneIdentity(
        state="unavailable",
        reason=reason[:256],
        identity_digest="",
        distribution_version="",
        binding_version="",
        binding_path="",
        binding_sha256="",
        native_core_version=(0, 0, 0),
        native_core_path="",
        native_core_size=0,
        native_core_sha256="",
        required_core_exports=(),
        target_operating_system=target_operating_system or host_os,
        target_abi=target_abi or host_abi,
        target_architecture=target_architecture or host_arch,
        target_endianness="little",
        target_mode="64",
        syntax="intel",
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_digest(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8", "strict")
    return hashlib.sha256(raw).hexdigest()


def _exact_mapping(value: object, keys: frozenset[str], reason: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise PackagedCapstoneUnavailable(reason)
    return value


def _exact_text(value: object, reason: str) -> str:
    if type(value) is not str or value == "":
        raise PackagedCapstoneUnavailable(reason)
    return str.__str__(value)


def _exact_int(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool or value < 0:
        raise PackagedCapstoneUnavailable(reason)
    return int(value)


def _exact_sha256(value: object, reason: str) -> str:
    text = _exact_text(value, reason).lower()
    if len(text) != 64 or any(character not in _HEX for character in text):
        raise PackagedCapstoneUnavailable(reason)
    return text


def _manifest_path(root: Path, value: object, reason: str) -> Path:
    relative = Path(_exact_text(value, reason))
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise PackagedCapstoneUnavailable(reason)
    candidate = (root.parent / relative).absolute()
    if path_contains_filesystem_alias(candidate):
        raise PackagedCapstoneUnavailable(reason)
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root.parent.resolve())
    except ValueError as exc:
        raise PackagedCapstoneUnavailable(reason) from exc
    return resolved


def _regular_file(path: Path, reason: str) -> None:
    if path_contains_filesystem_alias(path) or not path.is_file():
        raise PackagedCapstoneUnavailable(reason)


def _validate_elf64_x86_64(path: Path, reason: str) -> None:
    with path.open("rb") as handle:
        header = handle.read(64)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise PackagedCapstoneUnavailable(reason)
    if header[4] != 2 or header[5] != 1 or header[6] != 1:
        raise PackagedCapstoneUnavailable(reason)
    if struct.unpack_from("<H", header, 18)[0] != 62:
        raise PackagedCapstoneUnavailable(reason)


def _validate_pe32_plus_x86_64_dll(path: Path, reason: str) -> None:
    with path.open("rb") as handle:
        dos = handle.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            raise PackagedCapstoneUnavailable(reason)
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        if pe_offset < 64 or pe_offset > path.stat().st_size - 26:
            raise PackagedCapstoneUnavailable(reason)
        handle.seek(pe_offset)
        header = handle.read(26)
    if len(header) != 26 or header[:4] != b"PE\0\0":
        raise PackagedCapstoneUnavailable(reason)
    machine, _sections, _time, _symbol_ptr, _symbol_count, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", header, 4
    )
    optional_magic = struct.unpack_from("<H", header, 24)[0]
    if machine != 0x8664 or optional_magic != 0x20B or optional_size < 0xF0:
        raise PackagedCapstoneUnavailable(reason)
    if characteristics & 0x2000 == 0:
        raise PackagedCapstoneUnavailable(reason)


def _normalize_target_record(value: object) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    record = _exact_mapping(value, _TARGET_RECORD_KEYS, "capstone_target_record_invalid")
    target = _exact_mapping(record["target"], _TARGET_KEYS, "capstone_target_manifest_invalid")
    core = _exact_mapping(record["native_core"], _CORE_KEYS, "capstone_core_manifest_invalid")
    provenance = _exact_mapping(
        record["provenance"], _PROVENANCE_KEYS, "capstone_provenance_manifest_invalid"
    )
    operating_system = _exact_text(target["operating_system"], "capstone_target_platform_invalid")
    architecture = _exact_text(target["architecture"], "capstone_target_architecture_invalid")
    if (operating_system, architecture) not in _EXPECTED_TARGETS:
        raise PackagedCapstoneUnavailable("capstone_target_platform_invalid")
    expected = {
        "linux": {
            "abi": "manylinux_2_17_x86_64",
            "binary_class": "ELF64",
            "binary_format": "elf",
            "filename": "libcapstone.so",
            "machine": "EM_X86_64",
            "path": "packaged_capstone_5_0_9/capstone/lib/libcapstone.so",
            "member": "capstone/lib/libcapstone.so",
            "wheel_filename": "capstone-5.0.9-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
            "wheel_sha256": "273fd8d747d2e35c88f91450be51a603ecfaafb00d96d9f315dcb8689c86193e",
            "wheel_size": 1485316,
            "wheel_tag": "py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64",
        },
        "windows": {
            "abi": "win_amd64",
            "binary_class": "PE32+",
            "binary_format": "pe",
            "filename": "capstone.dll",
            "machine": "IMAGE_FILE_MACHINE_AMD64",
            "path": "packaged_capstone_5_0_9/capstone/lib/capstone.dll",
            "member": "capstone/lib/capstone.dll",
            "wheel_filename": "capstone-5.0.9-py3-none-win_amd64.whl",
            "wheel_sha256": "732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0",
            "wheel_size": 1273459,
            "wheel_tag": "py3-none-win_amd64",
        },
    }[operating_system]
    if target["abi"] != expected["abi"] or target["endianness"] != "little":
        raise PackagedCapstoneUnavailable("capstone_target_abi_invalid")
    if target["modes"] != ["64"] or target["syntax"] != "intel":
        raise PackagedCapstoneUnavailable("capstone_target_mode_invalid")
    for field in ("binary_class", "binary_format", "filename", "machine", "path"):
        if core[field] != expected[field]:
            raise PackagedCapstoneUnavailable("capstone_core_platform_invalid")
    if core["exported_api"] != "capstone_c_api_5_0":
        raise PackagedCapstoneUnavailable("capstone_core_architecture_invalid")
    exports_raw = core["required_exports"]
    if type(exports_raw) is not list:
        raise PackagedCapstoneUnavailable("capstone_core_exports_invalid")
    required_exports = tuple(
        _exact_text(item, "capstone_core_exports_invalid") for item in exports_raw
    )
    if required_exports != _REQUIRED_EXPORTS:
        raise PackagedCapstoneUnavailable("capstone_core_exports_invalid")
    if provenance["package_index_identity"] != "pypi:capstone==5.0.9":
        raise PackagedCapstoneUnavailable("capstone_provenance_package_index_invalid")
    expected_provenance = {
        "native_core_member": expected["member"],
        "wheel_filename": expected["wheel_filename"],
        "wheel_sha256": expected["wheel_sha256"],
        "wheel_size": expected["wheel_size"],
        "wheel_tag": expected["wheel_tag"],
    }
    for field, expected_value in expected_provenance.items():
        if provenance[field] != expected_value:
            raise PackagedCapstoneUnavailable("capstone_provenance_identity_invalid")
    _exact_sha256(core["sha256"], "capstone_core_sha256_invalid")
    _exact_int(core["size"], "capstone_core_size_invalid")
    return target, core, provenance


def validate_packaged_capstone_target(
    root: object,
    *,
    operating_system: str,
    architecture: str,
) -> PackagedCapstoneIdentity:
    """Validate the exact manifest-selected target without loading its library."""
    try:
        if not isinstance(root, Path):
            raise PackagedCapstoneUnavailable("capstone_package_root_invalid")
        if type(operating_system) is not str or type(architecture) is not str:
            raise PackagedCapstoneUnavailable("capstone_target_selector_invalid")
        package_root = root.absolute()
        if path_contains_filesystem_alias(package_root) or not package_root.is_dir():
            raise PackagedCapstoneUnavailable("capstone_package_root_unavailable")
        manifest_path = package_root / "dependency_manifest.json"
        _regular_file(manifest_path, "capstone_manifest_unavailable")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest = _exact_mapping(manifest, _MANIFEST_KEYS, "capstone_manifest_fields_invalid")
        if manifest["schema_version"] != PACKAGED_CAPSTONE_MANIFEST_SCHEMA_VERSION:
            raise PackagedCapstoneUnavailable("capstone_manifest_schema_invalid")
        if manifest["distribution_name"] != "capstone":
            raise PackagedCapstoneUnavailable("capstone_distribution_name_invalid")
        if manifest["distribution_version"] != _EXPECTED_DISTRIBUTION_VERSION:
            raise PackagedCapstoneUnavailable("capstone_distribution_version_invalid")
        if manifest["binding_version"] != _EXPECTED_BINDING_VERSION:
            raise PackagedCapstoneUnavailable("capstone_binding_version_invalid")
        identity_record = dict(manifest)
        declared_identity = _exact_sha256(
            identity_record.pop("dependency_identity_sha256"),
            "capstone_dependency_identity_invalid",
        )
        if _canonical_digest(identity_record) != declared_identity:
            raise PackagedCapstoneUnavailable("capstone_dependency_identity_mismatch")
        if declared_identity != PACKAGED_CAPSTONE_DEPENDENCY_IDENTITY:
            raise PackagedCapstoneUnavailable("capstone_dependency_identity_unpinned")

        binding = _exact_mapping(
            manifest["binding"],
            frozenset({"module", "path", "sha256", "size", "upstream_sha256"}),
            "capstone_binding_manifest_invalid",
        )
        version = _exact_mapping(
            manifest["native_core_version"],
            frozenset({"extra", "major", "minor"}),
            "capstone_core_version_manifest_invalid",
        )
        license_record = _exact_mapping(
            manifest["license"], frozenset({"path", "sha256"}), "capstone_license_manifest_invalid"
        )
        packaging = _exact_mapping(
            manifest["packaging"],
            frozenset({"patch_path", "patch_sha256", "patch_size", "policy"}),
            "capstone_packaging_manifest_invalid",
        )
        if binding["module"] != "packaged_capstone_5_0_9.capstone":
            raise PackagedCapstoneUnavailable("capstone_binding_module_invalid")
        if binding["upstream_sha256"] != "6f8a27fe069aa89a46974e189b5365d56eb5e02c2fd581d2fbfad7fbba51549f":
            raise PackagedCapstoneUnavailable("capstone_binding_upstream_sha256_unpinned")
        version_tuple = (
            _exact_int(version["major"], "capstone_core_version_invalid"),
            _exact_int(version["minor"], "capstone_core_version_invalid"),
            _exact_int(version["extra"], "capstone_core_version_invalid"),
        )
        if version_tuple != (5, 0, 1280):
            raise PackagedCapstoneUnavailable("capstone_core_version_invalid")
        if packaging["policy"] != "repository_packaged_core_only_no_fallback_preload_validation_v3":
            raise PackagedCapstoneUnavailable("capstone_packaging_policy_invalid")

        targets = manifest["targets"]
        if type(targets) is not list or len(targets) != len(_EXPECTED_TARGETS):
            raise PackagedCapstoneUnavailable("capstone_targets_manifest_invalid")
        selected: tuple[dict[str, object], dict[str, object], dict[str, object]] | None = None
        seen: set[tuple[str, str]] = set()
        ordered_keys: list[tuple[str, str]] = []
        for value in targets:
            target, core, provenance = _normalize_target_record(value)
            key = (str(target["operating_system"]), str(target["architecture"]))
            if key in seen:
                raise PackagedCapstoneUnavailable("capstone_target_duplicate")
            seen.add(key)
            ordered_keys.append(key)
            if key == (operating_system, architecture):
                selected = target, core, provenance
        if seen != _EXPECTED_TARGETS or ordered_keys != sorted(ordered_keys):
            raise PackagedCapstoneUnavailable("capstone_targets_manifest_invalid")
        if selected is None:
            raise PackagedCapstoneUnavailable("capstone_target_unavailable")
        target, core, _provenance = selected

        binding_path = _manifest_path(package_root, binding["path"], "capstone_binding_path_invalid")
        core_path = _manifest_path(package_root, core["path"], "capstone_core_path_invalid")
        license_path = _manifest_path(package_root, license_record["path"], "capstone_license_path_invalid")
        patch_path = _manifest_path(package_root, packaging["patch_path"], "capstone_packaging_patch_path_invalid")
        for path, reason in (
            (binding_path, "capstone_binding_unavailable"),
            (core_path, "capstone_core_unavailable"),
            (license_path, "capstone_license_unavailable"),
            (patch_path, "capstone_packaging_patch_unavailable"),
        ):
            _regular_file(path, reason)
        if binding_path.stat().st_size != _exact_int(binding["size"], "capstone_binding_size_invalid"):
            raise PackagedCapstoneUnavailable("capstone_binding_size_mismatch")
        if core_path.stat().st_size != _exact_int(core["size"], "capstone_core_size_invalid"):
            raise PackagedCapstoneUnavailable("capstone_core_size_mismatch")
        if _sha256(binding_path) != _exact_sha256(binding["sha256"], "capstone_binding_sha256_invalid"):
            raise PackagedCapstoneUnavailable("capstone_binding_sha256_mismatch")
        if _sha256(core_path) != _exact_sha256(core["sha256"], "capstone_core_sha256_invalid"):
            raise PackagedCapstoneUnavailable("capstone_core_sha256_mismatch")
        if _sha256(license_path) != _exact_sha256(license_record["sha256"], "capstone_license_sha256_invalid"):
            raise PackagedCapstoneUnavailable("capstone_license_sha256_mismatch")
        if patch_path.stat().st_size != _exact_int(packaging["patch_size"], "capstone_packaging_patch_size_invalid"):
            raise PackagedCapstoneUnavailable("capstone_packaging_patch_size_mismatch")
        if _sha256(patch_path) != _exact_sha256(packaging["patch_sha256"], "capstone_packaging_patch_sha256_invalid"):
            raise PackagedCapstoneUnavailable("capstone_packaging_patch_sha256_mismatch")
        if core["binary_format"] == "elf":
            _validate_elf64_x86_64(core_path, "capstone_core_elf_identity_invalid")
        elif core["binary_format"] == "pe":
            _validate_pe32_plus_x86_64_dll(core_path, "capstone_core_pe_identity_invalid")
        else:
            raise PackagedCapstoneUnavailable("capstone_core_platform_invalid")
        return PackagedCapstoneIdentity(
            state="available",
            reason="",
            identity_digest=declared_identity,
            distribution_version=_EXPECTED_DISTRIBUTION_VERSION,
            binding_version=_EXPECTED_BINDING_VERSION,
            binding_path=str(binding_path),
            binding_sha256=str(binding["sha256"]),
            native_core_version=version_tuple,
            native_core_path=str(core_path),
            native_core_size=int(core["size"]),
            native_core_sha256=str(core["sha256"]),
            required_core_exports=_REQUIRED_EXPORTS,
            target_operating_system=str(target["operating_system"]),
            target_abi=str(target["abi"]),
            target_architecture=str(target["architecture"]),
            target_endianness=str(target["endianness"]),
            target_mode=str(target["modes"][0]),
            syntax=str(target["syntax"]),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, PackagedCapstoneUnavailable) as exc:
        reason = str(exc) if str(exc) else type(exc).__name__
        return unavailable_capstone_identity(
            reason,
            target_operating_system=operating_system,
            target_architecture=architecture,
            target_abi="win_amd64" if operating_system == "windows" else "manylinux_2_17_x86_64",
        )


def validate_packaged_capstone(root: object = _PACKAGE_ROOT) -> PackagedCapstoneIdentity:
    """Validate the package for the current host without loading any native library."""
    operating_system, architecture, _abi = _host_target()
    if (operating_system, architecture) not in _EXPECTED_TARGETS:
        reason = (
            "capstone_host_operating_system_unsupported"
            if operating_system not in {item[0] for item in _EXPECTED_TARGETS}
            else "capstone_host_architecture_unsupported"
        )
        return unavailable_capstone_identity(reason)
    return validate_packaged_capstone_target(
        root,
        operating_system=operating_system,
        architecture=architecture,
    )


def packaged_capstone_resource_state() -> PackagedCapstoneIdentity:
    """Return the fixed host-qualified package state before native loading."""
    return validate_packaged_capstone(_PACKAGE_ROOT)


PACKAGED_CAPSTONE_RESOURCE_STATE = packaged_capstone_resource_state()


def require_packaged_capstone() -> PackagedCapstoneIdentity:
    """Require the validated immutable default package before loading its core."""
    identity = PACKAGED_CAPSTONE_RESOURCE_STATE
    if not identity.available:
        raise PackagedCapstoneUnavailable(identity.reason or "capstone_unavailable")
    return identity


__all__ = (
    "PACKAGED_CAPSTONE_DEPENDENCY_IDENTITY",
    "PACKAGED_CAPSTONE_MANIFEST_SCHEMA_VERSION",
    "PACKAGED_CAPSTONE_RESOURCE_STATE",
    "PackagedCapstoneIdentity",
    "PackagedCapstoneUnavailable",
    "packaged_capstone_resource_state",
    "require_packaged_capstone",
    "unavailable_capstone_identity",
    "validate_packaged_capstone",
    "validate_packaged_capstone_target",
)
