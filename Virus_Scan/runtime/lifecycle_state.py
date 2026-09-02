"""Owned runtime lifecycle state.

Phase C removes bootstrap/top-level lifecycle mutation from the retired shared
STATE mapping.  Startup flags and completed phases are owned here, exposed as
immutable snapshots, and mirrored only as RuntimeRoot events for telemetry.
"""
from __future__ import annotations

from types import MappingProxyType
from threading import RLock
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.governance_inputs import runtime_int, runtime_text
from Virus_Scan.runtime.immutable_core import freeze_runtime_value
from Virus_Scan.runtime.mutation_coordinator import get_runtime_root


class RuntimeLifecycleState:
    """Single owner for bootstrap and top-level initialization state."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._initialized = False
        self._top_level_initialized = False
        self._top_level_initializing = False
        self._phases_completed: list[str] = []
        self._bootstrap_registration_module_count = 0
        self._bootstrap_registration_validated = False
        self._dependency_providers_registered = False
        self._input_evidence: list[Mapping[str, object]] = []
        self._emission_failures: list[Mapping[str, object]] = []

    def snapshot(self) -> Mapping[str, object]:
        with self._lock:
            return MappingProxyType({
                "initialized": self._initialized,
                "top_level_initialized": self._top_level_initialized,
                "top_level_initializing": self._top_level_initializing,
                "phases_completed": tuple(self._phases_completed),
                "bootstrap_registration_module_count": self._bootstrap_registration_module_count,
                "bootstrap_registration_validated": self._bootstrap_registration_validated,
                "dependency_providers_registered": self._dependency_providers_registered,
                "BOOTSTRAP_REGISTRATION_MODULE_COUNT": self._bootstrap_registration_module_count,
                "BOOTSTRAP_REGISTRATION_VALIDATED": self._bootstrap_registration_validated,
                "BOOTSTRAP_DEPENDENCY_PROVIDERS_REGISTERED": self._dependency_providers_registered,
                "_INITIALIZED": self._initialized,
                "_TOP_LEVEL_INITIALIZED": self._top_level_initialized,
                "_TOP_LEVEL_INITIALIZING": self._top_level_initializing,
                "_TOP_LEVEL_INIT_PHASES_COMPLETED": tuple(self._phases_completed),
                "input_evidence": tuple(self._input_evidence),
                "emission_failures": tuple(self._emission_failures),
            })

    def is_initialized(self) -> bool:
        with self._lock:
            return self._initialized

    def mark_bootstrap_registration_validated(self, module_count: int) -> None:
        count, issues = runtime_int(
            module_count,
            field_name="bootstrap_registration_module_count",
            default=0,
        )
        with self._lock:
            self._input_evidence.extend(issues)
            self._bootstrap_registration_module_count = count
            self._bootstrap_registration_validated = not issues
        self._emit(
            "bootstrap_registration_validated",
            {"module_count": count, "input_evidence": issues},
        )

    def mark_dependency_providers_registered(self) -> None:
        with self._lock:
            self._dependency_providers_registered = True
        self._emit("dependency_providers_registered", {})

    def begin_top_level(self) -> None:
        with self._lock:
            if self._top_level_initialized:
                return
            if self._top_level_initializing:
                exception_message = "runtime initialization re-entered before finalization"
                raise RuntimeError(exception_message)
            self._top_level_initializing = True
            self._phases_completed = []
        self._emit("top_level_begin", {})

    def complete_phase(self, phase_name: str) -> None:
        phase, issues = runtime_text(
            phase_name,
            field_name="runtime_lifecycle_phase",
            default="input_rejected",
        )
        with self._lock:
            self._input_evidence.extend(issues)
            self._phases_completed.append(phase)
        self._emit(
            "top_level_phase_completed",
            {"phase": phase, "input_evidence": issues},
        )

    def finish_top_level(self) -> None:
        with self._lock:
            self._top_level_initialized = True
            self._top_level_initializing = False
        self._emit("top_level_finished", {})

    def fail_top_level(self) -> None:
        with self._lock:
            self._top_level_initialized = False
            self._top_level_initializing = False
        self._emit("top_level_failed", {})

    def mark_initialized(self) -> None:
        with self._lock:
            self._initialized = True
        self._emit("runtime_initialized", {})

    def _emit(self, kind: str, payload: Mapping[str, object]) -> None:
        try:
            get_runtime_root().emit("config", kind, payload)
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            failure = freeze_runtime_value(
                {
                    "runtime_lifecycle_emission_failed": True,
                    "kind": kind,
                    "error_type": no_hook_type_name(exc),
                    "final_json_must_record": True,
                    "checkpoint_must_record": True,
                    "replay_must_record": True,
                }
            )
            with self._lock:
                self._emission_failures.append(failure)


_LIFECYCLE_STATE = RuntimeLifecycleState()


def get_lifecycle_state() -> RuntimeLifecycleState:
    return _LIFECYCLE_STATE


__all__ = ("RuntimeLifecycleState", "get_lifecycle_state")
