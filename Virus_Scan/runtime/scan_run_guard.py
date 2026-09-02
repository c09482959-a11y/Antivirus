"""Single-parent scan run guard.

Prevents accidental duplicate parent scans of the same target/output from
appending a fresh scan lifecycle into an active run log. Queue children and
in-memory worker processes are explicitly excluded; this guard owns only the
user-facing parent scan lifecycle.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from dataclasses import dataclass

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_owner_field,
    no_hook_exact_nonnegative_int,
    no_hook_mapping_items,
    no_hook_plain_instance_dict,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
import errno
import hashlib
import json
import os
import time
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from Virus_Scan.runtime.resource_paths import scan_logs_dir, program_root
from Virus_Scan.runtime.platform_filesystem_durability import flush_open_writable_file
from threading import RLock
from types import SimpleNamespace

if TYPE_CHECKING:
    from collections.abc import Callable

class ParentScanGuardState:
    """Lifecycle owner for the active parent-scan lock path.

    Stage213 removes module-global rebinding from the parent scan guard.  The
    state object serializes lock ownership transitions explicitly and keeps the
    module from using ``global`` mutation for scan lifecycle state.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._active_lock: Path | None = None

    def set_active(self, lock: Path) -> None:
        with self._lock:
            self._active_lock = lock

    def consume_active(self) -> Path | None:
        with self._lock:
            lock = self._active_lock
            self._active_lock = None
            return lock


_PARENT_SCAN_GUARD_STATE = ParentScanGuardState()
_STDLIB_PATH_TYPES = (Path, PosixPath, WindowsPath, PurePosixPath, PureWindowsPath)


def _guard_field_name(field_name: object, *, default: str = "parent_scan_guard_input") -> str:
    text, reason = no_hook_text(
        field_name,
        missing_reason="parent_scan_guard_field_missing",
        unsupported_reason="parent_scan_guard_field_rejected",
    )
    if reason or text == "":
        return default
    return text


def _guard_text(value: object, field_name: str, *, allow_blank: bool = False) -> str:
    field_text = _guard_field_name(field_name)
    if type(value) in _STDLIB_PATH_TYPES:
        text = PurePath.as_posix(value)
        reason = ""
    else:
        text, reason = no_hook_text(
            value,
            missing_reason=field_text + "_missing",
            unsupported_reason=field_text + "_rejected",
        )
    if reason or (text == "" and not allow_blank):
        raise ValueError(reason or field_text + "_blank")
    return text


def _guard_args_state(args: object) -> dict[object, object]:
    items = no_hook_mapping_items(args)
    state: dict[object, object] | None
    if items is not None:
        state = dict(items)
    elif type(args) is SimpleNamespace:
        state = {
            "dir": no_hook_exact_owner_field(args, SimpleNamespace, "dir"),
            "scan_log_root": no_hook_exact_owner_field(args, SimpleNamespace, "scan_log_root"),
        }
    else:
        state = no_hook_plain_instance_dict(args)
    if (
        state is None
        or "dir" not in state
        or "scan_log_root" not in state
        or dict.get(state, "dir") is None
        or dict.get(state, "scan_log_root") is None
    ):
        raise TypeError("parent_scan_guard_args_rejected")
    return state


def _norm_path(value: object, field_name: str) -> str:
    text = _guard_text(value, field_name)
    return os.path.abspath(os.path.expanduser(text))


@dataclass(frozen=True)
class _PidProbeResult:
    alive: bool
    evidence: str


def _pid_probe(pid: object, *, kill_probe: Callable[[int, int], None] | None = None) -> _PidProbeResult:
    pid_i, reason = no_hook_exact_nonnegative_int(
        pid,
        reason="parent_scan_guard_pid_rejected",
        non_finite_reason="parent_scan_guard_pid_rejected",
        allow_exact_text=True,
    )
    if reason:
        return _PidProbeResult(True, reason)
    if pid_i <= 0:
        return _PidProbeResult(True, "parent_scan_guard_pid_nonpositive")
    if pid_i == os.getpid():
        return _PidProbeResult(True, "parent_scan_guard_current_process")
    probe = os.kill if kill_probe is None else kill_probe
    try:
        probe(pid_i, 0)
        return _PidProbeResult(True, "parent_scan_guard_pid_alive")
    except ProcessLookupError:
        return _PidProbeResult(False, "parent_scan_guard_pid_not_found")
    except PermissionError:
        record_suppressed_failure(
            "parent_scan_guard_pid_probe_permission_denied",
            PermissionError("parent_scan_guard_pid_probe_permission_denied"),
            domain="runtime",
        )
        return _PidProbeResult(True, "parent_scan_guard_pid_permission_denied")
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return _PidProbeResult(False, "parent_scan_guard_pid_esrch")
        record_suppressed_failure(
            "parent_scan_guard_pid_probe_failed",
            exc,
            domain="runtime",
        )
        return _PidProbeResult(True, "parent_scan_guard_pid_probe_failed")


def _pid_alive(pid: object) -> bool:
    return _pid_probe(pid).alive


def _lock_root(scan_log_root: object) -> Path:
    if scan_log_root is None:
        base = scan_logs_dir()
    else:
        base = Path(_norm_path(scan_log_root, "parent_scan_guard_scan_log_root"))
    base.mkdir(parents=True, exist_ok=True)
    return base / ".umige_active_scans"


def _lock_path(args_state: dict[object, object]) -> Path:
    target = _norm_path(
        dict.get(args_state, "dir"), "parent_scan_guard_target"
    )
    scan_log_root_value = dict.get(args_state, "scan_log_root")
    scan_log_root = _norm_path(scan_log_root_value, "parent_scan_guard_scan_log_root")
    digest_input = (target + "\n" + scan_log_root).encode('utf-8', 'surrogatepass')
    digest = hashlib.sha256(digest_input).hexdigest()[:32]
    root = _lock_root(scan_log_root_value)
    root.mkdir(parents=True, exist_ok=True)
    return root / (digest + ".lock.json")


def _guard_env_value(environ_get: object, name: str) -> str:
    env_name = _guard_field_name(name, default="env")
    value = environ_get(env_name, "")
    reason_prefix = "parent_scan_guard_env_" + env_name
    text, reason = no_hook_text(
        value,
        missing_reason=reason_prefix + "_missing",
        unsupported_reason=reason_prefix + "_rejected",
    )
    if reason and value is not None:
        raise ValueError(reason)
    return text.lower()


def _read_lock_payload(lock: Path) -> dict[str, object]:
    payload = json.loads(lock.read_text(encoding="utf-8", errors="replace"))
    if type(payload) is not dict:
        raise ValueError("parent_scan_guard_lock_payload_rejected")
    return payload


def _guard_display(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="parent_scan_guard_display_missing",
        unsupported_reason="parent_scan_guard_display_rejected",
    )
    return text if not reason else "<" + no_hook_type_name(value) + ">"


def acquire_parent_scan_guard(args: object, *, environ_get: object=os.environ.get) -> Path | None:
    """Acquire a deterministic parent-scan guard or raise SystemExit.

    The guard is intentionally skipped for scheduler children. A duplicate
    parent usually means a wrapper restarted the scanner while the previous scan
    was still active, which looks like a mid-run reboot in the log and risks
    output/cache races. Environment access is an explicit dependency for direct
    policy validation without mutating process environment globals.
    """
    if any(
        _guard_env_value(environ_get, name) == "1"
        for name in (
            "UMIGE_PROCESS_SHARD",
            "UMIGE_PROCESS_QUEUE",
            "UMIGE_INMEMORY_WORKER",
        )
    ):
        return None
    if _guard_env_value(
        environ_get, "UMIGE_DISABLE_PARENT_SCAN_GUARD"
    ) in {"1", "true", "yes", "on"}:
        return None
    args_state = _guard_args_state(args)
    lock = _lock_path(args_state)
    payload = {
        'pid': os.getpid(),
        'started_at': time.time(),
        'target': _norm_path(
            dict.get(args_state, "dir"), "parent_scan_guard_target"
        ),
        'scan_log_root': _norm_path(
            dict.get(args_state, "scan_log_root"), "parent_scan_guard_scan_log_root"
        ),
        'program_root': PurePath.as_posix(program_root()),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    while True:
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            try:
                os.write(fd, raw.encode('utf-8'))
                try:
                    flush_open_writable_file(fd)
                except OSError as exc:
                    record_suppressed_failure("parent_scan_guard_fsync_failed", exc, domain="runtime")
            finally:
                os.close(fd)
            _PARENT_SCAN_GUARD_STATE.set_active(lock)
            return lock
        except FileExistsError:
            try:
                existing = _read_lock_payload(lock)
            except RECOVERABLE_RUNTIME_ERRORS as exc:
                record_suppressed_failure(
                    "parent_scan_guard_lock_read_failed", exc, domain="runtime"
                )
                raise SystemExit(
                    "active UMIGE scan lock is unreadable; refusing to "
                    "remove it without verified ownership"
                ) from exc
            if not _pid_alive(dict.get(existing, "pid")):
                try:
                    lock.unlink()
                    continue
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    record_suppressed_failure(
                        "parent_scan_guard_stale_lock_remove_failed",
                        exc,
                        domain="runtime",
                    )
            raise SystemExit(
                'active UMIGE scan already running for this target/output; '
                "pid=" + _guard_display(dict.get(existing, 'pid', 'unknown')) + " "
                "target=" + _guard_display(dict.get(existing, 'target', '')) + " "
                "output=" + _guard_display(dict.get(existing, 'output', '')) + ". "
                'Refusing duplicate parent scan to prevent mid-run reboot/output races.'
            ) from None


def release_parent_scan_guard() -> None:
    lock = _PARENT_SCAN_GUARD_STATE.consume_active()
    if lock is None:
        return
    try:
        existing = _read_lock_payload(lock)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_suppressed_failure(
            "parent_scan_guard_release_lock_read_failed",
            exc,
            domain="runtime",
        )
        raise RuntimeError("parent_scan_guard_release_lock_unreadable") from exc
    try:
        pid, reason = no_hook_exact_nonnegative_int(
            dict.get(existing, "pid"),
            reason="parent_scan_guard_release_pid_rejected",
            non_finite_reason="parent_scan_guard_release_pid_rejected",
            allow_exact_text=True,
        )
        if reason:
            record_suppressed_failure(
                "parent_scan_guard_release_pid_rejected",
                ValueError(reason),
                domain="runtime",
            )
            return
        if pid == os.getpid():
            lock.unlink(missing_ok=True)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_suppressed_failure("parent_scan_guard_release_failed", exc, domain="runtime")
