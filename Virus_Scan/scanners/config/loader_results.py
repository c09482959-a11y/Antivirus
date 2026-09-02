"""Immutable scanner policy load-result contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, TYPE_CHECKING

if TYPE_CHECKING:
    from Virus_Scan.scanners.config.contracts import (
        ArchivePolicySnapshot,
        BinaryPolicySnapshot,
        EnginePolicySnapshot,
        FiletypePolicySnapshot,
        PayloadPolicySnapshot,
        PicklePolicySnapshot,
        RawChunkPolicySnapshot,
        ScannerConfigFailure,
        ScannerLimitsPolicySnapshot,
        TextPolicySnapshot,
    )

class ScannerPolicyLoadResultMixin:
    __slots__ = ()

    snapshot: object
    failure: ScannerConfigFailure | None

    @property
    def ok(self) -> bool:
        return self.snapshot is not None and self.failure is None

    @property
    def failure_evidence(self) -> tuple[Mapping[str, object], ...]:
        if self.failure is None:
            return ()
        return self.failure.failure_evidence


@dataclass(frozen=True, slots=True)
class PayloadPolicyLoadResult(ScannerPolicyLoadResultMixin):
    snapshot: PayloadPolicySnapshot | None
    failure: ScannerConfigFailure | None = None


@dataclass(frozen=True, slots=True)
class PicklePolicyLoadResult(ScannerPolicyLoadResultMixin):
    snapshot: PicklePolicySnapshot | None
    failure: ScannerConfigFailure | None = None


@dataclass(frozen=True, slots=True)
class RawChunkPolicyLoadResult(ScannerPolicyLoadResultMixin):
    snapshot: RawChunkPolicySnapshot | None
    failure: ScannerConfigFailure | None = None


@dataclass(frozen=True, slots=True)
class TextPolicyLoadResult(ScannerPolicyLoadResultMixin):
    snapshot: TextPolicySnapshot | None
    failure: ScannerConfigFailure | None = None


@dataclass(frozen=True, slots=True)
class FiletypePolicyLoadResult(ScannerPolicyLoadResultMixin):
    snapshot: FiletypePolicySnapshot | None
    failure: ScannerConfigFailure | None = None


@dataclass(frozen=True, slots=True)
class EnginePolicyLoadResult(ScannerPolicyLoadResultMixin):
    snapshot: EnginePolicySnapshot | None
    failure: ScannerConfigFailure | None = None


@dataclass(frozen=True, slots=True)
class BinaryPolicyLoadResult(ScannerPolicyLoadResultMixin):
    snapshot: BinaryPolicySnapshot | None
    failure: ScannerConfigFailure | None = None


@dataclass(frozen=True, slots=True)
class ArchivePolicyLoadResult(ScannerPolicyLoadResultMixin):
    snapshot: ArchivePolicySnapshot | None
    failure: ScannerConfigFailure | None = None


@dataclass(frozen=True, slots=True)
class ScannerLimitsPolicyLoadResult(ScannerPolicyLoadResultMixin):
    snapshot: ScannerLimitsPolicySnapshot | None
    failure: ScannerConfigFailure | None = None

__all__ = (
    "ArchivePolicyLoadResult",
    "BinaryPolicyLoadResult",
    "EnginePolicyLoadResult",
    "FiletypePolicyLoadResult",
    "PayloadPolicyLoadResult",
    "PicklePolicyLoadResult",
    "RawChunkPolicyLoadResult",
    "ScannerLimitsPolicyLoadResult",
    "TextPolicyLoadResult",
)
