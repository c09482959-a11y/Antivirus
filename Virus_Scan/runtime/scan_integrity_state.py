"""Explicit runtime-owned per-file scan integrity state.

The core path/scanning helpers record integrity metadata for files that move
through scheduler and raw-queue execution.  The mutable mapping is owned by the
runtime context and bound during bootstrap, not stored as a core module global.
"""
from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from threading import RLock
from typing import Mapping, NoReturn

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_text,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value


_SCAN_INTEGRITY_KEY_REQUIRED = "scan integrity key is required"


def _raise_scan_integrity_key_required() -> NoReturn:
    raise ValueError(_SCAN_INTEGRITY_KEY_REQUIRED)


def _freeze_scan_integrity_value(value: object) -> object:
    return freeze_runtime_value(value)

def _detach_scan_integrity_value(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        return {
            str.__str__(key): _detach_scan_integrity_value(item)
            for key, item in items
            if type(key) is str
        }
    if type(value) is tuple:
        return tuple(_detach_scan_integrity_value(item) for item in value)
    if type(value) is list:
        return [_detach_scan_integrity_value(item) for item in value]
    return value


def _scan_integrity_key(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="scan_integrity_key_missing",
        unsupported_reason="scan_integrity_key_rejected",
    )
    if reason or text == "":
        _raise_scan_integrity_key_required()
    return text


class ScanIntegrityStateNotConfigured(RuntimeError):
    """Raised when scan integrity state is used before runtime ownership exists."""


@dataclass
class RuntimeScanIntegrityState:
    """Runtime-owned storage for per-path scan integrity metadata."""

    _lock: RLock = field(default_factory=RLock)
    _entries: dict[str, tuple[int, object]] = field(default_factory=dict)
    _generation: int = 0

    def clear(self, key: str) -> None:
        key_text = _scan_integrity_key(key)
        with self._lock:
            self._entries.pop(key_text, None)

    def clear_all(self) -> None:
        """Invalidate all scan-integrity entries owned by this state in O(1)."""
        with self._lock:
            self._generation += 1

    def get(self, key: str) -> dict[str, object]:
        key_text = _scan_integrity_key(key)
        with self._lock:
            record = self._entries.get(key_text)
            if record is None:
                return {}
            generation, value = record
            if generation != self._generation:
                return {}
            return _detach_scan_integrity_value(value)

    def set(self, key: str, meta: Mapping[str, object]) -> None:
        key_text = _scan_integrity_key(key)
        with self._lock:
            self._entries[key_text] = (
                self._generation,
                _freeze_scan_integrity_value({} if meta is None else meta),
            )


_SCAN_INTEGRITY_BINDING: ContextVar[RuntimeScanIntegrityState | None] = ContextVar(
    'umige_runtime_scan_integrity_state',
    default=None,
)


def configure_runtime_scan_integrity_state(state: RuntimeScanIntegrityState) -> None:
    """Bind scan integrity storage owned by the active runtime context."""
    if not isinstance(state, RuntimeScanIntegrityState):
        exception_message = 'runtime scan integrity state must be RuntimeScanIntegrityState'
        raise TypeError(exception_message)
    _SCAN_INTEGRITY_BINDING.set(state)




def bind_runtime_scan_integrity_state(state: RuntimeScanIntegrityState) -> Token[RuntimeScanIntegrityState | None]:
    """Bind scan integrity storage and return a token for bounded reset."""
    if not isinstance(state, RuntimeScanIntegrityState):
        exception_message = 'runtime scan integrity state must be RuntimeScanIntegrityState'
        raise TypeError(exception_message)
    return _SCAN_INTEGRITY_BINDING.set(state)


def reset_runtime_scan_integrity_state_binding(token: Token[RuntimeScanIntegrityState | None]) -> None:
    """Reset the scan integrity ContextVar binding created for one test."""
    _SCAN_INTEGRITY_BINDING.reset(token)

def scan_integrity_state() -> RuntimeScanIntegrityState:
    """Return the explicitly bound scan integrity state for this runtime context."""
    state = _SCAN_INTEGRITY_BINDING.get()
    if state is None:
        exception_message = 'runtime scan integrity state not configured'
        raise ScanIntegrityStateNotConfigured(exception_message)
    return state


__all__ = (
    'RuntimeScanIntegrityState',
    'ScanIntegrityStateNotConfigured',
    'bind_runtime_scan_integrity_state',
    'configure_runtime_scan_integrity_state',
    'reset_runtime_scan_integrity_state_binding',
    'scan_integrity_state',
)
