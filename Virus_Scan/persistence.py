"""Canonical persistence ownership import boundary.

The startup/Nuitka validation contract imports ``Virus_Scan.persistence`` as the
package-level persistence owner.  This module owns final parent-process model and
scan-cache flushing directly so runtime orchestration does not route persistence
through an extra service package boundary.
"""
from __future__ import annotations

from typing import Protocol

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.publication.api import flush_all_persistent_models
from Virus_Scan.runtime.api import (
    PERSISTENCE_FAILURE,
    ProfilePersistenceState,
    failure_tag,
    log_error,
    profile_persistence_state,
)


class _PersistentRuntime(Protocol):
    parent_cli: bool

    def get(self, key: str, default: object = None) -> object:
        ...

    def has(self, key: str) -> bool:
        ...


class _PersistenceArgs(Protocol):
    strict: bool


def _persistent_flush_failed(result: object) -> bool:
    items = no_hook_mapping_items(result, allow_dict_subclass=True)
    if items is None:
        return False
    for key, value in items:
        if key == "ok":
            return value is not True
    return False


def _persistent_flush_failure_status(exc: BaseException) -> dict[str, object]:
    return {
        "schema_version": "persistent_model_flush_v1",
        "ok": False,
        "stores": {},
        "error_type": no_hook_type_name(exc),
    }


def flush_persistent_state(runtime: _PersistentRuntime, args: _PersistenceArgs) -> object:
    """Flush parent-owned persistent state at the controlled scan boundary."""
    if not runtime.parent_cli:
        return None
    try:
        result = flush_all_persistent_models(force=True)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error(
            failure_tag(PERSISTENCE_FAILURE)
            + " final persistent model flush failed: "
            + no_hook_type_name(exc)
        )
        if args.strict:
            raise
        return _persistent_flush_failure_status(exc)
    if _persistent_flush_failed(result):
        log_error(
            failure_tag(PERSISTENCE_FAILURE)
            + " final persistent model flush failed: persistent_model_flush_failed"
        )
        if args.strict:
            raise RuntimeError("persistent_model_flush_failed")
    return result


__all__ = (
    "ProfilePersistenceState",
    "flush_persistent_state",
    "profile_persistence_state",
)
