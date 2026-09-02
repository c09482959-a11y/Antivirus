"""Strict runtime owner for the validated repository-packaged Capstone core."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import threading
from types import ModuleType

from packaged_capstone_5_0_9.integrity import (
    PACKAGED_CAPSTONE_DEPENDENCY_IDENTITY,
    PACKAGED_CAPSTONE_RESOURCE_STATE,
    PackagedCapstoneIdentity,
    unavailable_capstone_identity,
)

NATIVE_DECODER_RUNTIME_SCHEMA_VERSION = "native_capstone_runtime_v2"
NATIVE_DECODER_SUBSYSTEM_NAME = "native_decoder"
_RUNTIME_LOCK = threading.RLock()
_RUNTIME: NativeDecoderRuntime | None = None


class NativeDecoderUnavailable(RuntimeError):
    """The sole packaged decoder cannot be used under its exact contract."""


@dataclass(frozen=True, slots=True)
class NativeDecoderRuntime:
    """One process-local binding proven to match the immutable package identity."""

    identity: PackagedCapstoneIdentity
    binding: ModuleType


@dataclass(frozen=True, slots=True)
class _BindingImportState:
    """Explicit module-import result without a fallback binding owner."""

    identity: PackagedCapstoneIdentity
    binding: ModuleType
    available: bool


try:
    from packaged_capstone_5_0_9 import capstone as _PACKAGED_CAPSTONE_BINDING
except (ImportError, OSError, RuntimeError, TypeError, ValueError) as _binding_error:
    _base_identity = PACKAGED_CAPSTONE_RESOURCE_STATE
    _binding_reason = (
        _base_identity.reason
        if not _base_identity.available
        else "capstone_binding_import_failed:" + type(_binding_error).__name__
    )
    _BINDING_IMPORT_STATE = _BindingImportState(
        identity=unavailable_capstone_identity(_binding_reason),
        binding=ModuleType("packaged_capstone_unavailable"),
        available=False,
    )
else:
    _BINDING_IMPORT_STATE = _BindingImportState(
        identity=PACKAGED_CAPSTONE_RESOURCE_STATE,
        binding=_PACKAGED_CAPSTONE_BINDING,
        available=True,
    )


def native_decoder_resource_state() -> PackagedCapstoneIdentity:
    """Return the immutable process-local package and binding state."""
    return _BINDING_IMPORT_STATE.identity


def open_native_decoder() -> NativeDecoderRuntime:
    """Return the sole statically imported packaged binding after exact checks."""
    global _RUNTIME
    with _RUNTIME_LOCK:
        if _RUNTIME is not None:
            return _RUNTIME
        identity = native_decoder_resource_state()
        if not identity.available or not _BINDING_IMPORT_STATE.available:
            raise NativeDecoderUnavailable(identity.reason or "capstone_unavailable")
        binding = _BINDING_IMPORT_STATE.binding
        module_file = getattr(binding, "__file__", "")
        module_path = Path(module_file).resolve() if type(module_file) is str else Path()
        if module_path != Path(identity.binding_path):
            raise NativeDecoderUnavailable("capstone_loaded_binding_path_mismatch")
        loaded_core = getattr(binding, "_cs", None)
        loaded_name = getattr(loaded_core, "_name", "")
        if type(loaded_name) is not str or Path(loaded_name).resolve() != Path(identity.native_core_path):
            raise NativeDecoderUnavailable("capstone_loaded_core_path_mismatch")
        if getattr(binding, "__version__", "") != identity.binding_version:
            raise NativeDecoderUnavailable("capstone_loaded_binding_version_mismatch")
        if tuple(binding.cs_version()) != identity.native_core_version:
            raise NativeDecoderUnavailable("capstone_loaded_core_version_mismatch")
        if getattr(binding, "CS_ARCH_X86", None) is None or getattr(binding, "CS_MODE_64", None) is None:
            raise NativeDecoderUnavailable("capstone_loaded_architecture_api_missing")
        if any(not hasattr(loaded_core, name) for name in identity.required_core_exports):
            raise NativeDecoderUnavailable("capstone_loaded_exported_api_mismatch")
        _RUNTIME = NativeDecoderRuntime(identity=identity, binding=binding)
        return _RUNTIME


__all__ = (
    "NATIVE_DECODER_RUNTIME_SCHEMA_VERSION",
    "NATIVE_DECODER_SUBSYSTEM_NAME",
    "NativeDecoderRuntime",
    "NativeDecoderUnavailable",
    "PACKAGED_CAPSTONE_DEPENDENCY_IDENTITY",
    "native_decoder_resource_state",
    "open_native_decoder",
)
