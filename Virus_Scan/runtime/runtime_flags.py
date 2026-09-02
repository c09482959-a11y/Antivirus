"""Lifecycle-owned mutable runtime flags.

Small boolean dirty/once flags were historically mutated with module-level
``global`` rebinding from cache, logging, and persistence code.  This owner keeps
those transitions explicit, lock-protected, and auditable without introducing
alternate paths or runtime mutation.
"""
from __future__ import annotations

from threading import RLock
from types import MappingProxyType

from Virus_Scan.runtime.governance_inputs import runtime_bool, runtime_text


def _flag_items(flags: dict[str, bool]) -> tuple[tuple[str, bool], ...]:
    return tuple(sorted(dict.items(flags)))


def _flag_name(value: object) -> str:
    name, issues = runtime_text(
        value, field_name="runtime_flag_name", default=""
    )
    if issues or name == "":
        raise ValueError("runtime_flag_name_rejected")
    return name


def _flag_value(value: object) -> bool:
    enabled, issues = runtime_bool(
        value, field_name="runtime_flag_value", default=False
    )
    if issues:
        raise ValueError("runtime_flag_value_rejected")
    return enabled


class RuntimeFlagOwner:
    """Single lifecycle owner for mutable boolean runtime flags."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._flags: dict[str, bool] = {
            "runtime_model_state_dirty": False,
            "yara_download_error_logged": False,
        }

    def get(self, name: str) -> bool:
        key = _flag_name(name)
        with self._lock:
            return self._flags.get(key, False)

    def set(self, name: str, *, value: bool) -> bool:
        key = _flag_name(name)
        enabled = _flag_value(value)
        with self._lock:
            self._flags[key] = enabled
            return enabled

    def mark(self, name: str) -> bool:
        return self.set(name, value=True)

    def clear(self, name: str) -> bool:
        return self.set(name, value=False)

    def claim_once(self, name: str) -> bool:
        """Atomically mark a flag true and return True only for the first claimer."""
        key = _flag_name(name)
        with self._lock:
            if self._flags.get(key, False):
                return False
            self._flags[key] = True
            return True

    def snapshot(self) -> MappingProxyType:
        with self._lock:
            return MappingProxyType(dict(_flag_items(self._flags)))


_RUNTIME_FLAGS = RuntimeFlagOwner()


def runtime_flag_get(name: str) -> bool:
    return _RUNTIME_FLAGS.get(name)


def runtime_flag_mark(name: str) -> bool:
    return _RUNTIME_FLAGS.mark(name)


def runtime_flag_clear(name: str) -> bool:
    return _RUNTIME_FLAGS.clear(name)


def runtime_flag_claim_once(name: str) -> bool:
    return _RUNTIME_FLAGS.claim_once(name)


__all__ = (
    "RuntimeFlagOwner",
    "runtime_flag_claim_once",
    "runtime_flag_clear",
    "runtime_flag_get",
    "runtime_flag_mark",
)
