"""Typed queue identity index outcomes and scalar parsing contracts."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    from collections.abc import Mapping

IdentityIndexMutationStatus = Literal["completed", "skipped", "rejected", "failed"]
IdentityIndexLookupStatus = Literal["hit", "miss", "expired", "rejected", "failed"]
IdentityIndexStorageStatus = Literal["resolved", "accepted", "loaded", "written", "missing", "rejected"]

@dataclass(frozen=True)
class IdentityIndexFloatOutcome:
    accepted: bool
    value: float
    reason: str

@dataclass(frozen=True)
class IdentityIndexMutationOutcome:
    status: IdentityIndexMutationStatus
    reason: str
    touched_entries: int = 0

@dataclass(frozen=True)
class IdentityIndexLookupOutcome:
    status: IdentityIndexLookupStatus
    reason: str
    identities: frozenset[str] = frozenset()

@dataclass(frozen=True)
class IdentityIndexQueueDirDecision:
    status: IdentityIndexStorageStatus
    reason: str
    path: Path | None = None

@dataclass(frozen=True)
class IdentityIndexKeyDigestDecision:
    status: IdentityIndexStorageStatus
    reason: str
    digest: str = ""

@dataclass(frozen=True)
class IdentityIndexPathDecision:
    status: IdentityIndexStorageStatus
    reason: str
    path: Path | None = None

@dataclass(frozen=True)
class IdentityIndexReadDecision:
    status: IdentityIndexStorageStatus
    reason: str
    payload: Mapping[str, object] | None = None

@dataclass(frozen=True)
class IdentityIndexSnapshotDecision:
    status: IdentityIndexStorageStatus
    reason: str
    identities: tuple[str, ...] = ()

@dataclass(frozen=True)
class IdentityIndexWriteDecision:
    status: IdentityIndexStorageStatus
    reason: str
    written: bool = False

def identity_index_nonnegative_float(value: object, *, reason: str) -> IdentityIndexFloatOutcome:
    if type(value) is int and type(value) is not bool:
        parsed = float(value)
    elif type(value) is float:
        if not math.isfinite(value):
            return IdentityIndexFloatOutcome(accepted=False, value=0.0, reason=reason)
        parsed = value
    else:
        return IdentityIndexFloatOutcome(accepted=False, value=0.0, reason=reason)
    if parsed < 0.0:
        return IdentityIndexFloatOutcome(accepted=False, value=0.0, reason=reason)
    return IdentityIndexFloatOutcome(accepted=True, value=parsed, reason="")

def identity_index_mutation_outcome(status: IdentityIndexMutationStatus, reason: str, *, touched_entries: int = 0) -> IdentityIndexMutationOutcome:
    return IdentityIndexMutationOutcome(status=status, reason=reason, touched_entries=touched_entries)

def identity_index_lookup_outcome(status: IdentityIndexLookupStatus, reason: str, identities: tuple[str, ...] = ()) -> IdentityIndexLookupOutcome:
    return IdentityIndexLookupOutcome(status=status, reason=reason, identities=frozenset(identities))

def identity_index_queue_dir_decision(status: IdentityIndexStorageStatus, reason: str, path: Path | None = None) -> IdentityIndexQueueDirDecision:
    return IdentityIndexQueueDirDecision(status=status, reason=reason, path=path)

def identity_index_key_digest_decision(status: IdentityIndexStorageStatus, reason: str, digest: str = "") -> IdentityIndexKeyDigestDecision:
    return IdentityIndexKeyDigestDecision(status=status, reason=reason, digest=digest)

def identity_index_path_decision(status: IdentityIndexStorageStatus, reason: str, path: Path | None = None) -> IdentityIndexPathDecision:
    return IdentityIndexPathDecision(status=status, reason=reason, path=path)

def identity_index_read_decision(status: IdentityIndexStorageStatus, reason: str, payload: Mapping[str, object] | None = None) -> IdentityIndexReadDecision:
    return IdentityIndexReadDecision(status=status, reason=reason, payload=payload)

def identity_index_snapshot_decision(status: IdentityIndexStorageStatus, reason: str, identities: tuple[str, ...] = ()) -> IdentityIndexSnapshotDecision:
    return IdentityIndexSnapshotDecision(status=status, reason=reason, identities=identities)

def identity_index_write_decision(status: IdentityIndexStorageStatus, reason: str, *, written: bool = False) -> IdentityIndexWriteDecision:
    return IdentityIndexWriteDecision(status=status, reason=reason, written=written)

__all__ = (
    "IdentityIndexFloatOutcome", "IdentityIndexKeyDigestDecision", "IdentityIndexLookupOutcome",
    "IdentityIndexLookupStatus", "IdentityIndexMutationOutcome", "IdentityIndexMutationStatus",
    "IdentityIndexPathDecision", "IdentityIndexQueueDirDecision", "IdentityIndexReadDecision",
    "IdentityIndexSnapshotDecision", "IdentityIndexStorageStatus", "IdentityIndexWriteDecision",
    "identity_index_key_digest_decision", "identity_index_lookup_outcome", "identity_index_mutation_outcome",
    "identity_index_nonnegative_float", "identity_index_path_decision", "identity_index_queue_dir_decision",
    "identity_index_read_decision", "identity_index_snapshot_decision", "identity_index_write_decision",
)
