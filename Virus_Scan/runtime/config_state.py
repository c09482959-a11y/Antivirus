"""Canonical runtime configuration owner for Phase C shared-state collapse.

Runtime configuration values such as deep scan mode, ILSpy path, and profile
storage paths are now read through this explicit owner.  The previous pattern made
configuration a mutable cross-module namespace.  This owner keeps those values
behind a lock-protected API; published state snapshots are derived from the owner
for old generated modules, but new/runtime code must read configuration here.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from threading import RLock

from Virus_Scan.contracts.no_hook_materialization import no_hook_text


_STDLIB_PATH_TYPES = (
    Path,
    PosixPath,
    WindowsPath,
    PurePosixPath,
    PureWindowsPath,
)


def _config_text(value: object, *, default: str, field_name: str) -> str:
    if value is None:
        return default
    if type(value) in _STDLIB_PATH_TYPES:
        text, reason = PurePath.as_posix(value), ""
    else:
        text, reason = no_hook_text(
            value,
            missing_reason=_config_state_reason(field_name, "_missing"),
            unsupported_reason=_config_state_reason(field_name, "_rejected"),
        )
    if reason:
        raise ValueError(_config_state_reason(field_name, " rejected"))
    text = text.strip()
    return text or default


def _config_state_reason(field_name: str, suffix: str) -> str:
    return f"{field_name}{suffix}"


def _config_path(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    text = _config_text(value, default="", field_name=field_name)
    if text.lower() in {"", "none", "null"}:
        return None
    return os.path.abspath(text)


@dataclass(frozen=True)
class RuntimeConfigSnapshot:
    deep_scan_mode: str
    ilspy_path: str | None
    profiles_dir: str | None
    profile_corruption_policy: str


class RuntimeConfigOwner:
    def __init__(self) -> None:
        self._lock = RLock()
        self._deep_scan_mode = (os.environ.get('UMIGE_DEEP_SCAN_MODE', 'auto') or 'auto').strip().lower() or 'auto'
        self._ilspy_path: str | None = None
        self._profiles_dir: str | None = None
        self._profile_corruption_policy = 'hard-fail'

    def set_deep_scan_mode(self, value: object) -> str:
        mode = _config_text(
            value, default="auto", field_name="deep_scan_mode"
        ).lower()
        with self._lock:
            self._deep_scan_mode = mode
        return mode

    def deep_scan_mode(self) -> str:
        with self._lock:
            return self._deep_scan_mode

    def set_ilspy_path(self, value: object) -> str | None:
        path = _config_path(value, field_name="ilspy_path")
        with self._lock:
            self._ilspy_path = path
        return path

    def ilspy_path(self, default: str | None = None) -> str | None:
        with self._lock:
            return self._ilspy_path if self._ilspy_path is not None else default

    def set_profiles_dir(self, value: object) -> str | None:
        path = _config_path(value, field_name="profiles_dir")
        with self._lock:
            self._profiles_dir = path
        return path

    def profiles_dir(self, default: str | None = None) -> str | None:
        with self._lock:
            return self._profiles_dir if self._profiles_dir is not None else default

    def set_profile_corruption_policy(self, value: object) -> str:
        policy = _config_text(
            value,
            default="hard-fail",
            field_name="profile_corruption_policy",
        ).lower().replace("_", "-")
        if policy not in {'hard-fail', 'quarantine'}:
            raise ValueError("unsupported profile corruption policy: " + policy)
        with self._lock:
            self._profile_corruption_policy = policy
        return policy

    def profile_corruption_policy(self, default: str = 'hard-fail') -> str:
        with self._lock:
            return self._profile_corruption_policy or default

    def snapshot(self) -> RuntimeConfigSnapshot:
        with self._lock:
            return RuntimeConfigSnapshot(
                deep_scan_mode=self._deep_scan_mode,
                ilspy_path=self._ilspy_path,
                profiles_dir=self._profiles_dir,
                profile_corruption_policy=self._profile_corruption_policy,
            )


_CONFIG_OWNER = RuntimeConfigOwner()


def configure_deep_scan_mode(value: object) -> str:
    return _CONFIG_OWNER.set_deep_scan_mode(value)


def get_deep_scan_mode(default: str = 'auto') -> str:
    mode = _CONFIG_OWNER.deep_scan_mode()
    return mode or default


def configure_ilspy_path(value: object) -> str | None:
    return _CONFIG_OWNER.set_ilspy_path(value)


def get_ilspy_path(default: str | None = None) -> str | None:
    return _CONFIG_OWNER.ilspy_path(default)


def configure_profiles_dir(value: object) -> str | None:
    return _CONFIG_OWNER.set_profiles_dir(value)


def get_profiles_dir(default: str | None = None) -> str | None:
    return _CONFIG_OWNER.profiles_dir(default)


def configure_profile_corruption_policy(value: object) -> str:
    return _CONFIG_OWNER.set_profile_corruption_policy(value)


def get_profile_corruption_policy(default: str = 'hard-fail') -> str:
    return _CONFIG_OWNER.profile_corruption_policy(default)


__all__ = (
    'RuntimeConfigOwner',
    'RuntimeConfigSnapshot',
    'configure_deep_scan_mode',
    'configure_ilspy_path',
    'configure_profile_corruption_policy',
    'configure_profiles_dir',
    'get_deep_scan_mode',
    'get_ilspy_path',
    'get_profile_corruption_policy',
    'get_profiles_dir',
)
