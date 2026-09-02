"""Typed optional psutil loader for scheduler backpressure telemetry."""
from __future__ import annotations

import importlib.util
from types import ModuleType
from typing import Protocol


class PsutilProcess(Protocol):
    def memory_info(self) -> object: ...


class PsutilTelemetryModule(Protocol):
    def cpu_percent(self, *, interval: object = None) -> object: ...
    def virtual_memory(self) -> object: ...
    def Process(self, pid: int) -> PsutilProcess: ...


class UnavailablePsutilModule:
    """Explicit optional-dependency sentinel for scheduler backpressure telemetry."""

    available = False
    dependency = "psutil"

    def cpu_percent(self, *, interval: object = None) -> object:
        del interval
        raise ImportError("psutil_unavailable")

    def virtual_memory(self) -> object:
        raise ImportError("psutil_unavailable")

    def Process(self, pid: int) -> PsutilProcess:
        del pid
        raise ImportError("psutil_unavailable")


class ImportedPsutilModule:
    available = True
    dependency = "psutil"

    def __init__(self, module: ModuleType) -> None:
        self._module = module

    def cpu_percent(self, *, interval: object = None) -> object:
        return getattr(self._module, "cpu_percent")(interval=interval)

    def virtual_memory(self) -> object:
        return getattr(self._module, "virtual_memory")()

    def Process(self, pid: int) -> PsutilProcess:
        return getattr(self._module, "Process")(pid)


def load_psutil() -> PsutilTelemetryModule:
    spec = importlib.util.find_spec("psutil")
    if spec is None or spec.loader is None:
        return UnavailablePsutilModule()
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return ImportedPsutilModule(module)


psutil = load_psutil()


__all__ = ("PsutilTelemetryModule", "psutil")
