"""Public replay-economics model contract.

Replay learning may decide when to attach parent-model replay metadata, but the
retention/compression policy for that metadata remains owned by replay economics.
Model callers use this bounded public API instead of importing
``Virus_Scan.models.replay_economics`` internals directly.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from types import MappingProxyType

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name

from Virus_Scan.models.replay_economics import (
    replay_compress_metadata as owner_replay_compress_metadata,
    replay_should_retain as owner_replay_should_retain,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

def _replay_retention_evidence(retain: bool, *, ready: bool, reason: str | None) -> Mapping[str, object]:
    degraded = reason is not None
    return MappingProxyType({
        "retain": retain,
        "ready": ready,
        "degraded": degraded,
        "unavailable_reason": reason,
        "evidence_type": "replay_economics_retention",
        "final_json_must_record": degraded,
        "replay_record_required": True,
    })


def replay_should_retain_evidence(result: object) -> Mapping[str, object]:
    """Return replay-retention decision evidence."""
    try:
        retained = owner_replay_should_retain(result)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _replay_retention_evidence(
            True,
            ready=False,
            reason="replay_retention_public_call_failed",
        )
    if type(retained) is not bool:
        return _replay_retention_evidence(
            True,
            ready=False,
            reason="replay_retention_result_invalid",
        )
    return _replay_retention_evidence(retained, ready=True, reason=None)


def replay_should_retain(result: object) -> bool:
    """Return the canonical replay-economics retention decision.

    Malformed public replay-result containers are fail-safe retained.
    Dropping them would erase the evidence needed to diagnose replay/model
    corruption.
    """
    evidence = replay_should_retain_evidence(result)
    retain = evidence.get("retain", True)
    return retain is True


def replay_compress_metadata(metadata: object) -> object:
    """Compress replay metadata through the canonical replay-economics owner."""
    try:
        return owner_replay_compress_metadata(metadata)
    except RECOVERABLE_RUNTIME_ERRORS:
        return {
            "value": "<" + no_hook_type_name(metadata) + ">",
            "unavailable_reason": "replay_metadata_compression_failed",
            "degraded": True,
            "final_json_must_record": True,
            "replay_record_required": True,
        }


__all__ = ("replay_compress_metadata", "replay_should_retain", "replay_should_retain_evidence")
