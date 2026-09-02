"""Immutable startup decision boundary for UMIGE.

Startup code owns argv handling, CLI parser execution, help/version exits, and
classification of the parsed command.  It does not import or execute scan
runtime modules.  Scan mode is represented as data and handed to the process
entrypoint, which may then enter the runtime-owned scan lifecycle.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


class StartupDecisionKind(str, Enum):
    HELP = "help"
    VERSION = "version"
    SCAN = "scan"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class RuntimeRequest:
    """Immutable request object passed from startup to runtime ownership."""

    args: object
    argv: Optional[Tuple[str, ...]] = None


@dataclass(frozen=True, slots=True)
class StartupDecision:
    """Startup-only decision result."""

    kind: StartupDecisionKind
    exit_code: int = 0
    runtime_request: RuntimeRequest | None = None

    @classmethod
    def help(cls, exit_code: int = 0) -> "StartupDecision":
        return cls(kind=StartupDecisionKind.HELP, exit_code=int(exit_code))

    @classmethod
    def version(cls, exit_code: int = 0) -> "StartupDecision":
        return cls(kind=StartupDecisionKind.VERSION, exit_code=int(exit_code))

    @classmethod
    def error(cls, exit_code: int) -> "StartupDecision":
        return cls(kind=StartupDecisionKind.ERROR, exit_code=int(exit_code))

    @classmethod
    def scan(cls, request: RuntimeRequest) -> "StartupDecision":
        return cls(kind=StartupDecisionKind.SCAN, exit_code=0, runtime_request=request)


__all__ = ("RuntimeRequest", "StartupDecision", "StartupDecisionKind")
