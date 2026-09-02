"""Queue-owned raw accumulator lock transitions.

The lock owner is isolated from accumulator count reconciliation so queue
accumulator state can be tested without mixing durable counter updates with
filesystem lock cleanup semantics.
"""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from types import BuiltinFunctionType, TracebackType
from typing import Self


from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.contracts.runtime_function_identity import RUNTIME_NATIVE_FUNCTION_TYPE
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_filesystem_path,
    scheduler_float,
)

_SAFE_RECORD_SUPPRESSED_TYPES = (RUNTIME_NATIVE_FUNCTION_TYPE, BuiltinFunctionType)
_RAW_ACCUMULATOR_DEPENDENCIES_MODULE = "Virus_Scan.scheduler.queue.raw_queue_accumulator"
_RAW_ACCUMULATOR_DEPENDENCIES_NAME = "RawAccumulatorDependencies"


def _raw_accumulator_record_suppressed(deps: object) -> tuple[object, str]:
    if deps is None:
        return None, "raw_accumulator_deps_record_scheduler_suppressed_missing"
    deps_type = type(deps)
    try:
        if type.__getattribute__(deps_type, "__getattribute__") is not object.__getattribute__:
            return None, "raw_accumulator_deps_record_scheduler_suppressed_instance_dict_rejected"
    except (AttributeError, TypeError, RuntimeError):
        return None, "raw_accumulator_deps_record_scheduler_suppressed_type_rejected"
    try:
        mro = type.__getattribute__(deps_type, "__mro__")
    except (AttributeError, TypeError, RuntimeError):
        return None, "raw_accumulator_deps_record_scheduler_suppressed_type_rejected"
    is_raw_accumulator_dependencies = False
    for cls in mro:
        try:
            cls_name = type.__getattribute__(cls, "__name__")
            cls_module = type.__getattribute__(cls, "__module__")
        except (AttributeError, TypeError, RuntimeError):
            return None, "raw_accumulator_deps_record_scheduler_suppressed_type_rejected"
        if (
            cls_module == _RAW_ACCUMULATOR_DEPENDENCIES_MODULE
            and cls_name == _RAW_ACCUMULATOR_DEPENDENCIES_NAME
        ):
            is_raw_accumulator_dependencies = True
            break
    if is_raw_accumulator_dependencies:
        record_suppressed = scheduler_exact_attr(deps, "record_scheduler_suppressed", owner_type=deps_type)
        if record_suppressed is None:
            return None, "raw_accumulator_deps_record_scheduler_suppressed_missing"
        if type(record_suppressed) not in _SAFE_RECORD_SUPPRESSED_TYPES:
            return None, "raw_accumulator_deps_record_scheduler_suppressed_callable_rejected"
        return record_suppressed, ""
    descriptor = None
    for cls in mro:
        try:
            class_dict = type.__getattribute__(cls, "__dict__")
        except (AttributeError, TypeError, RuntimeError):
            return None, "raw_accumulator_deps_record_scheduler_suppressed_type_rejected"
        candidate = class_dict.get("record_scheduler_suppressed")
        if candidate is not None:
            descriptor = candidate
            break
    if descriptor is None:
        return None, "raw_accumulator_deps_record_scheduler_suppressed_missing"
    if type(descriptor) not in _SAFE_RECORD_SUPPRESSED_TYPES:
        return None, "raw_accumulator_deps_record_scheduler_suppressed_callable_rejected"
    try:
        return descriptor.__get__(deps, deps_type), ""
    except (AttributeError, TypeError, RuntimeError):
        return None, "raw_accumulator_deps_record_scheduler_suppressed_method_bind_failed"


class GlobalRawAccumLock:
    """Directory lock for one raw accumulator record with stale-lock recovery."""

    def __init__(self, lock_dir: object, name: object, timeout: float = 30.0, *, deps: object) -> None:
        record_suppressed, deps_reason = _raw_accumulator_record_suppressed(deps)
        if deps_reason:
            raise TypeError("raw accumulator lock requires scheduler suppression dependencies: " + deps_reason)
        lock_root, lock_reason = scheduler_filesystem_path(lock_dir)
        if lock_reason:
            raise TypeError("raw accumulator lock directory rejected: " + lock_reason)
        name_text, name_reason = no_hook_text(
            name,
            missing_reason="raw_accumulator_lock_name_missing",
            unsupported_reason="raw_accumulator_lock_name_rejected",
        )
        if name_reason or not name_text:
            raise TypeError("raw accumulator lock name rejected: " + (name_reason or "raw_accumulator_lock_name_missing"))
        timeout_value, timeout_reason = scheduler_float(
            timeout,
            minimum=0.0,
            reason="raw_accumulator_lock_timeout_rejected",
        )
        if timeout_reason:
            raise TypeError("raw accumulator lock timeout rejected: " + timeout_reason)
        self.deps = deps
        self.record_scheduler_suppressed = record_suppressed
        self.path = Path(lock_root) / (name_text + ".lock")
        self.timeout = timeout_value
        self.acquired = False

    def __enter__(self) -> Self:
        deadline = time.time() + self.timeout
        path_text = Path.__str__(self.path)
        while True:
            try:
                Path(path_text).mkdir()
                self.acquired = True
                return self
            except FileExistsError:
                try:
                    age = time.time() - os.path.getmtime(path_text)
                    if age > max(60.0, self.timeout * 2):
                        shutil.rmtree(path_text, ignore_errors=True)
                        continue
                except OSError as exc:
                    self.record_scheduler_suppressed("raw_accumulator_stale_lock_probe_failed", exc)
                if time.time() > deadline:
                    raise TimeoutError("global raw accumulator lock timeout: " + path_text) from None
                time.sleep(0.025)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self.acquired:
            path_text = Path.__str__(self.path)
            try:
                Path(path_text).rmdir()
            except OSError as cleanup_exc:
                try:
                    shutil.rmtree(path_text, ignore_errors=False)
                except OSError as cleanup_exc2:
                    self.record_scheduler_suppressed("raw_accumulator_lock_cleanup_failed", cleanup_exc2)
                else:
                    self.record_scheduler_suppressed("raw_accumulator_lock_rmdir_failed", cleanup_exc)


__all__ = ("GlobalRawAccumLock",)
