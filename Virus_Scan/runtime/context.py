"""Explicit runtime context for the modular UMIGE application."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from Virus_Scan.runtime.config import RuntimeConfig
from Virus_Scan.runtime.environment import RuntimeEnvironmentOwner
from Virus_Scan.runtime.ownership import RuntimeStateOwner
from Virus_Scan.runtime.telemetry import RuntimeTelemetry


@dataclass
class RuntimeContext:
    """Thin dependency container plus the single runtime-state owner."""

    owner: RuntimeStateOwner = field(default_factory=RuntimeStateOwner)
    initialized: bool = False
    parent_cli: bool = True
    scan_started_at: float = 0.0
    config: RuntimeConfig = field(default_factory=RuntimeConfig.from_args)
    telemetry: RuntimeTelemetry = field(default_factory=RuntimeTelemetry)
    environment: RuntimeEnvironmentOwner = field(default_factory=RuntimeEnvironmentOwner)
    virustotal_runtime: object | None = field(default=None, repr=False)

    def initialize(self, initializer: object | None = None) -> "RuntimeContext":
        if initializer is None:
            raise RuntimeError("runtime_initializer_required")
        self.owner.refresh(initializer())
        self.owner.install_config(self.config)
        self.owner.install_telemetry(self.telemetry)
        self.initialized = True
        return self

    def get(self, name: str, default: Optional[object] = None) -> object:
        return self.owner.get(name, default)

    def set(self, name: str, value: object, *, domain: str = "runtime") -> object:
        return self.owner.set(name, value, domain=domain)

    def has(self, name: str) -> bool:
        return self.owner.has(name)
