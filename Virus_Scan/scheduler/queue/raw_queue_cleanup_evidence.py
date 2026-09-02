"""Replayable typed decisions for raw queue cleanup boundaries."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PosixPath, WindowsPath


from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.evidence_pairs import JsonEvidencePairs, scheduler_evidence_pairs

_PATH_TYPES = (PosixPath, WindowsPath)


@dataclass(frozen=True)
class RawQueueCleanupPathDecision:
    path: Path | None
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


@dataclass(frozen=True)
class RawQueueCleanupNameDecision:
    text: str
    accepted: bool
    reason: str
    evidence: JsonEvidencePairs


@dataclass(frozen=True)
class RawQueueDiagnosticCleanupDecision:
    removed: int
    completed: bool
    reason: str
    evidence: JsonEvidencePairs


def raw_queue_cleanup_path_decision(value: object) -> RawQueueCleanupPathDecision:
    if type(value) is str:
        path = Path(str.__str__(value))
        return RawQueueCleanupPathDecision(
            path=path,
            accepted=True,
            reason="accepted_cleanup_path_text",
            evidence=scheduler_evidence_pairs(
                ("decision", "raw_queue_cleanup_path"),
                ("accepted", True),
                ("reason", "accepted_cleanup_path_text"),
                ("value_type", "str"),
            ),
        )
    if type(value) in _PATH_TYPES:
        return RawQueueCleanupPathDecision(
            path=value,
            accepted=True,
            reason="accepted_cleanup_path_object",
            evidence=scheduler_evidence_pairs(
                ("decision", "raw_queue_cleanup_path"),
                ("accepted", True),
                ("reason", "accepted_cleanup_path_object"),
                ("value_type", no_hook_type_name(value)),
            ),
        )
    reason = "unsafe_cleanup_path_rejected"
    return RawQueueCleanupPathDecision(
        path=None,
        accepted=False,
        reason=reason,
        evidence=scheduler_evidence_pairs(
            ("decision", "raw_queue_cleanup_path"),
            ("accepted", False),
            ("reason", reason),
            ("value_type", no_hook_type_name(value)),
        ),
    )


def raw_queue_cleanup_name_decision(value: object, *, field_name: str) -> RawQueueCleanupNameDecision:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_" + field_name,
        unsupported_reason="unsafe_" + field_name + "_rejected",
    )
    accepted = reason == "" and text != ""
    decision_reason = "accepted_" + field_name if accepted else reason or "empty_" + field_name
    return RawQueueCleanupNameDecision(
        text=text if accepted else str.__str__(""),
        accepted=accepted,
        reason=decision_reason,
        evidence=scheduler_evidence_pairs(
            ("decision", "raw_queue_cleanup_name"),
            ("field_name", field_name),
            ("accepted", accepted),
            ("reason", decision_reason),
            ("value_type", no_hook_type_name(value)),
        ),
    )


def raw_queue_diagnostic_cleanup_decision(removed: int, *, completed: bool, reason: str) -> RawQueueDiagnosticCleanupDecision:
    safe_removed = removed if type(removed) is int and type(removed) is not bool and removed >= 0 else 0
    safe_reason = reason if type(reason) is str and reason else "raw_queue_diagnostic_cleanup_recorded"
    return RawQueueDiagnosticCleanupDecision(
        removed=safe_removed,
        completed=completed is True,
        reason=safe_reason,
        evidence=scheduler_evidence_pairs(
            ("decision", "raw_queue_diagnostic_cleanup"),
            ("removed", safe_removed),
            ("completed", completed is True),
            ("reason", safe_reason),
        ),
    )


__all__ = (
    "RawQueueCleanupNameDecision",
    "RawQueueCleanupPathDecision",
    "RawQueueDiagnosticCleanupDecision",
    "raw_queue_cleanup_name_decision",
    "raw_queue_cleanup_path_decision",
    "raw_queue_diagnostic_cleanup_decision",
)
