"""Canonical immutable runtime platform and Python ABI identity."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import platform
import sys
import sysconfig

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

RUNTIME_PLATFORM_IDENTITY_SCHEMA_VERSION = "runtime_platform_identity_v1"
_SUPPORTED_TARGETS = (
    (("linux", "x86_64"), ("manylinux_2_17_x86_64", "elf")),
    (("windows", "x86_64"), ("win_amd64", "pe")),
)


def runtime_platform_target_key(identity: "RuntimePlatformIdentity") -> str:
    """Return the canonical supported-target key for one frozen runtime identity."""
    if type(identity) is not RuntimePlatformIdentity:
        raise TypeError("runtime_platform_identity_required")
    return "|".join((
        identity.operating_system, identity.architecture, identity.abi, identity.binary_format,
    ))


def supported_runtime_target_keys() -> tuple[str, ...]:
    """Return every declared first-class runtime target from this single platform owner."""
    return tuple(
        "|".join((operating_system, architecture, abi, binary_format))
        for (operating_system, architecture), (abi, binary_format) in _SUPPORTED_TARGETS
    )


def _canonical_digest(record: dict[str, object]) -> str:
    raw = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8", "strict")
    return hashlib.sha256(raw).hexdigest()


def _normalized_operating_system() -> str:
    observation = (os.name, sys.platform, platform.system())
    if observation == ("posix", "linux", "Linux"):
        return "linux"
    if observation == ("nt", "win32", "Windows"):
        return "windows"
    return "unsupported"


def _normalized_architecture() -> str:
    value = platform.machine().casefold()
    if value in {"amd64", "x64", "x86_64"}:
        return "x86_64"
    if value in {"arm64", "aarch64"}:
        return "aarch64"
    return value or "unknown"


@dataclass(frozen=True, slots=True)
class RuntimePlatformIdentity:
    """Exact process platform identity frozen into a scan generation."""

    operating_system: str
    architecture: str
    abi: str
    binary_format: str
    python_implementation: str
    python_version: str
    python_abi: str
    byteorder: str
    pointer_bits: int
    schema_version: str = RUNTIME_PLATFORM_IDENTITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        operating_system = exact_bounded_text(
            self.operating_system, "runtime_platform_operating_system_invalid", maximum=32,
        )
        architecture = exact_bounded_text(
            self.architecture, "runtime_platform_architecture_invalid", maximum=32,
        )
        abi = exact_bounded_text(self.abi, "runtime_platform_abi_invalid", maximum=128)
        binary_format = exact_bounded_text(
            self.binary_format, "runtime_platform_binary_format_invalid", maximum=32,
        )
        python_implementation = exact_bounded_text(
            self.python_implementation,
            "runtime_platform_python_implementation_invalid",
            maximum=32,
        )
        python_version = exact_bounded_text(
            self.python_version, "runtime_platform_python_version_invalid", maximum=64,
        )
        python_abi = exact_bounded_text(
            self.python_abi, "runtime_platform_python_abi_invalid", maximum=192,
        )
        byteorder = exact_bounded_text(
            self.byteorder, "runtime_platform_byteorder_invalid", maximum=16,
        )
        if byteorder not in {"little", "big"}:
            raise ValueError("runtime_platform_byteorder_invalid")
        if type(self.pointer_bits) is not int or type(self.pointer_bits) is bool:
            raise TypeError("runtime_platform_pointer_bits_invalid")
        if self.pointer_bits not in {32, 64}:
            raise ValueError("runtime_platform_pointer_bits_invalid")
        schema = exact_bounded_text(
            self.schema_version, "runtime_platform_schema_invalid", maximum=128,
        )
        if schema != RUNTIME_PLATFORM_IDENTITY_SCHEMA_VERSION:
            raise ValueError("runtime_platform_schema_invalid")
        object.__setattr__(self, "operating_system", operating_system)
        object.__setattr__(self, "architecture", architecture)
        object.__setattr__(self, "abi", abi)
        object.__setattr__(self, "binary_format", binary_format)
        object.__setattr__(self, "python_implementation", python_implementation)
        object.__setattr__(self, "python_version", python_version)
        object.__setattr__(self, "python_abi", python_abi)
        object.__setattr__(self, "byteorder", byteorder)
        object.__setattr__(self, "schema_version", schema)

    def to_record(self) -> dict[str, object]:
        return {
            "abi": self.abi,
            "architecture": self.architecture,
            "binary_format": self.binary_format,
            "byteorder": self.byteorder,
            "operating_system": self.operating_system,
            "pointer_bits": self.pointer_bits,
            "python_abi": self.python_abi,
            "python_implementation": self.python_implementation,
            "python_version": self.python_version,
            "schema_version": self.schema_version,
        }

    @property
    def digest(self) -> str:
        return _canonical_digest(self.to_record())

    @classmethod
    def from_record(cls, record: object) -> "RuntimePlatformIdentity":
        if type(record) is not dict:
            raise TypeError("runtime_platform_record_invalid")
        expected = {
            "abi", "architecture", "binary_format", "byteorder",
            "operating_system", "pointer_bits", "python_abi",
            "python_implementation", "python_version", "schema_version",
        }
        if set(record) != expected:
            raise ValueError("runtime_platform_record_keys_invalid")
        return cls(
            operating_system=record["operating_system"],
            architecture=record["architecture"],
            abi=record["abi"],
            binary_format=record["binary_format"],
            python_implementation=record["python_implementation"],
            python_version=record["python_version"],
            python_abi=record["python_abi"],
            byteorder=record["byteorder"],
            pointer_bits=record["pointer_bits"],
            schema_version=record["schema_version"],
        )


def runtime_platform_identity() -> RuntimePlatformIdentity:
    """Return the exact normalized identity for the current interpreter process."""
    operating_system = _normalized_operating_system()
    architecture = _normalized_architecture()
    target = next(
        (value for key, value in _SUPPORTED_TARGETS if key == (operating_system, architecture)),
        None,
    )
    if target is None:
        abi = "unsupported"
        binary_format = "unknown"
    else:
        abi, binary_format = target
    python_abi_value = sysconfig.get_config_var("SOABI")
    if type(python_abi_value) is not str or python_abi_value == "":
        cache_tag = getattr(sys.implementation, "cache_tag", "")
        python_abi_value = cache_tag if type(cache_tag) is str and cache_tag else "unknown"
    implementation_name = getattr(sys.implementation, "name", "")
    if type(implementation_name) is not str or implementation_name == "":
        implementation_name = "unknown"
    return RuntimePlatformIdentity(
        operating_system=operating_system,
        architecture=architecture,
        abi=abi,
        binary_format=binary_format,
        python_implementation=implementation_name,
        python_version=".".join(str(item) for item in sys.version_info[:3]),
        python_abi=python_abi_value,
        byteorder=sys.byteorder,
        pointer_bits=64 if sys.maxsize > 2**32 else 32,
    )


__all__ = (
    "RUNTIME_PLATFORM_IDENTITY_SCHEMA_VERSION",
    "RuntimePlatformIdentity",
    "runtime_platform_identity",
    "runtime_platform_target_key",
    "supported_runtime_target_keys",
)
