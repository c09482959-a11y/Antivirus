"""Lifecycle-owned path/runtime option state.

This module owns mutable path-runtime values that were previously rebound as
module globals inside ``core.paths`` during CLI startup.  Keeping these values
behind an explicit owner removes hidden global rebinding while preserving the
same deterministic process-local runtime behavior.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import math
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from threading import RLock
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_text,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value


_STDLIB_PATH_TYPES = (
    Path,
    PosixPath,
    WindowsPath,
    PurePosixPath,
    PureWindowsPath,
)


def _freeze_runtime_mapping(value: object) -> Mapping[str, object]:
    frozen = freeze_runtime_value(value)
    if type(frozen) is MappingProxyType:
        return frozen
    return freeze_runtime_value(
        {
            "value": None,
            "unavailable_reason": "path_runtime_context_mapping_rejected",
        }
    )


def _path_runtime_text(value: object, default: str) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="path_runtime_text_missing",
        unsupported_reason="path_runtime_text_rejected",
    )
    text = text.strip().lower()
    return text if not reason and text else default


def _path_runtime_optional_text(value: object) -> str | None:
    if value is None:
        return None
    if type(value) in _STDLIB_PATH_TYPES:
        text, reason = PurePath.as_posix(value), ""
    else:
        text, reason = no_hook_text(
            value,
            missing_reason="path_runtime_text_missing",
            unsupported_reason="path_runtime_text_rejected",
        )
    return None if reason or text == "" else text


def _path_runtime_bool(value: object, *, default: bool = False) -> bool:
    if type(value) is bool:
        return value
    if type(value) is int and type(value) is not bool:
        return value != 0
    if type(value) is str:
        text = str.__str__(value).strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off", ""}:
            return False
    return default


def _path_runtime_timeout(value: object) -> int:
    if type(value) is int and type(value) is not bool:
        return 60 if value == 0 else max(1, value)
    if type(value) is float and math.isfinite(value) and value.is_integer():
        parsed = int(value)
        return 60 if parsed == 0 else max(1, parsed)
    parsed, reason = no_hook_exact_nonnegative_int(value, default=60)
    return 60 if reason else max(1, parsed)


@dataclass(frozen=True)
class PathRuntimeSnapshot:
    cli_engine_hint: str
    scan_engine_hint: str
    scan_engine_hint_context: Mapping[str, object]
    ilspy_path: str | None
    use_ilspy: bool
    ilspy_timeout_sec: int
    ilspy_dump_root: str | None

    def __post_init__(self) -> None:
        if type(self) is not PathRuntimeSnapshot:
            exception_message = "path runtime snapshot owner rejected"
            raise TypeError(exception_message)
        object.__setattr__(self, "cli_engine_hint", _path_runtime_text(self.cli_engine_hint, "auto"))
        object.__setattr__(self, "scan_engine_hint", _path_runtime_text(self.scan_engine_hint, "unknown"))
        object.__setattr__(self, "scan_engine_hint_context", _freeze_runtime_mapping(self.scan_engine_hint_context))
        use_ilspy = _path_runtime_bool(self.use_ilspy)
        object.__setattr__(self, "ilspy_path", _path_runtime_optional_text(self.ilspy_path))
        object.__setattr__(self, "use_ilspy", use_ilspy)
        object.__setattr__(self, "ilspy_timeout_sec", _path_runtime_timeout(self.ilspy_timeout_sec))
        object.__setattr__(self, "ilspy_dump_root", _path_runtime_optional_text(self.ilspy_dump_root))


@dataclass
class PathRuntimeStateOwner:
    _lock: RLock = field(default_factory=RLock)
    _cli_engine_hint: str = 'auto'
    _scan_engine_hint: str = 'unknown'
    _scan_engine_hint_context: Mapping[str, object] = field(default_factory=dict)
    _ilspy_path: str | None = None
    _use_ilspy: bool = False
    _ilspy_timeout_sec: int = 60
    _ilspy_dump_root: str | None = None
    _ilspy_cache: dict[str, str | None] = field(default_factory=dict)

    def configure_engine(self, cli_hint: object, scan_hint: object, context: object) -> None:
        with self._lock:
            self._cli_engine_hint = _path_runtime_text(cli_hint, "auto")
            self._scan_engine_hint = _path_runtime_text(scan_hint, "unknown")
            frozen_context = _freeze_runtime_mapping({} if context is None else context)
            self._scan_engine_hint_context = frozen_context

    def configure_ilspy(self, *, path: str | None, use_ilspy: bool, timeout_sec: int, dump_root: str | None) -> None:
        with self._lock:
            self._ilspy_path = _path_runtime_optional_text(path)
            self._use_ilspy = _path_runtime_bool(use_ilspy)
            self._ilspy_timeout_sec = _path_runtime_timeout(timeout_sec)
            self._ilspy_dump_root = _path_runtime_optional_text(dump_root)
            self._ilspy_cache.clear()

    def set_ilspy_dump_root(self, value: str | None) -> str | None:
        with self._lock:
            self._ilspy_dump_root = _path_runtime_optional_text(value)
            return self._ilspy_dump_root

    def ilspy_dump_root(self) -> str | None:
        with self._lock:
            return self._ilspy_dump_root

    def ilspy_cache_get(self, key: str) -> str | None:
        with self._lock:
            return self._ilspy_cache.get(key)

    def ilspy_cache_contains(self, key: str) -> bool:
        with self._lock:
            return key in self._ilspy_cache

    def ilspy_cache_set(self, key: str, value: str | None) -> str | None:
        with self._lock:
            self._ilspy_cache[key] = value
            return value

    def snapshot(self) -> PathRuntimeSnapshot:
        with self._lock:
            return PathRuntimeSnapshot(
                cli_engine_hint=self._cli_engine_hint,
                scan_engine_hint=self._scan_engine_hint,
                scan_engine_hint_context=_freeze_runtime_mapping(self._scan_engine_hint_context),
                ilspy_path=self._ilspy_path,
                use_ilspy=self._use_ilspy,
                ilspy_timeout_sec=self._ilspy_timeout_sec,
                ilspy_dump_root=self._ilspy_dump_root,
            )


_PATH_RUNTIME_OWNER = PathRuntimeStateOwner()


def path_runtime_owner() -> PathRuntimeStateOwner:
    return _PATH_RUNTIME_OWNER


__all__ = ('PathRuntimeSnapshot', 'PathRuntimeStateOwner', 'path_runtime_owner')
