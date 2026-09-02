"""Canonical runtime initialization ordered caller."""
from __future__ import annotations

from collections.abc import Callable, Iterator

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import get_lifecycle_state
from Virus_Scan.core import initialize_core
from Virus_Scan.core.init_parts.cache_init import init_finalize
from Virus_Scan.scheduler.api.runner import initialize_scheduler
from Virus_Scan.models.api.init_contracts import initialize_models
from Virus_Scan.detection.api.init_contracts import initialize_detection
from Virus_Scan.yara import initialize_yara
from Virus_Scan.scanners.api.init_contracts import initialize_scanners
from Virus_Scan.reporting import initialize_reporting
from types import MappingProxyType


RUNTIME_INITIALIZATION_PHASES = (
    "core",
    "scheduler",
    "models",
    "detection",
    "yara",
    "scanners",
    "reporting",
)

_RUNTIME_INITIALIZER_BY_PHASE = MappingProxyType({
    "core": initialize_core,
    "scheduler": initialize_scheduler,
    "models": initialize_models,
    "detection": initialize_detection,
    "yara": initialize_yara,
    "scanners": initialize_scanners,
    "reporting": initialize_reporting,
})


def _iter_runtime_initializers() -> Iterator[tuple[str, Callable[[], object]]]:
    for phase_name in RUNTIME_INITIALIZATION_PHASES:
        yield phase_name, _RUNTIME_INITIALIZER_BY_PHASE[phase_name]


def run_top_level_init() -> object:
    """Run runtime initialization once in canonical phase order."""
    lifecycle = get_lifecycle_state()
    snapshot = lifecycle.snapshot()
    if snapshot.get("top_level_initializing"):
        raise RuntimeError("runtime initialization re-entered before finalization")
    if snapshot.get("top_level_initialized"):
        return snapshot
    lifecycle.begin_top_level()
    try:
        for phase_name, initializer in _iter_runtime_initializers():
            initializer()
            lifecycle.complete_phase(phase_name)
        init_finalize()
        lifecycle.finish_top_level()
        return lifecycle.snapshot()
    except RECOVERABLE_RUNTIME_ERRORS:
        lifecycle.fail_top_level()
        raise


__all__ = ("RUNTIME_INITIALIZATION_PHASES", "run_top_level_init")
