"""Replayable typed decisions for raw queue duplicate-guard inputs."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text


@dataclass(frozen=True)
class RawQueueDuplicateMappingDecision:
    """No-hook mapping materialization result for duplicate-guard job data."""

    mapping: dict[str, object]
    accepted: bool
    reason: str

    @classmethod
    def rejected(cls, reason: str) -> "RawQueueDuplicateMappingDecision":
        return cls(mapping={}, accepted=False, reason=reason)


@dataclass(frozen=True)
class RawQueueDuplicateTextDecision:
    """No-hook queue-listing text materialization decision."""

    text: str
    accepted: bool
    reason: str

    @classmethod
    def rejected(cls, reason: str) -> "RawQueueDuplicateTextDecision":
        return cls(text="", accepted=False, reason=reason)


@dataclass(frozen=True)
class RawQueueDuplicateClaimNameDecision:
    """No-hook claim-path filename decision for duplicate guard replay."""

    name: str
    accepted: bool
    reason: str

    @classmethod
    def rejected(cls, reason: str) -> "RawQueueDuplicateClaimNameDecision":
        return cls(name="", accepted=False, reason=reason)


def raw_queue_duplicate_job_mapping(value: object) -> RawQueueDuplicateMappingDecision:
    """Materialize exact string-key job mapping or emit a replayable rejection."""
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is None:
        return RawQueueDuplicateMappingDecision.rejected("raw_queue_duplicate_job_mapping_rejected")
    return RawQueueDuplicateMappingDecision(mapping=scheduler_str_key_mapping_from_items(items), accepted=True, reason="")


def raw_queue_duplicate_name_text(value: object) -> RawQueueDuplicateTextDecision:
    """Materialize a queue-listing name without hiding rejected names as blank text."""
    text, reason = no_hook_text(
        value,
        missing_reason="missing_raw_queue_duplicate_name",
        unsupported_reason="unsafe_raw_queue_duplicate_name_rejected",
    )
    if reason:
        return RawQueueDuplicateTextDecision.rejected(reason)
    if text == "":
        return RawQueueDuplicateTextDecision.rejected("empty_raw_queue_duplicate_name")
    return RawQueueDuplicateTextDecision(text=text, accepted=True, reason="")


def raw_queue_duplicate_claim_name(claim_path: object) -> RawQueueDuplicateClaimNameDecision:
    """Materialize the current claim filename without using filesystem hooks."""
    text, reason = scheduler_path_text(claim_path)
    if reason:
        return RawQueueDuplicateClaimNameDecision.rejected(reason)
    if text == "":
        return RawQueueDuplicateClaimNameDecision.rejected("empty_raw_queue_duplicate_claim_path")
    return RawQueueDuplicateClaimNameDecision(name=Path(text).name, accepted=True, reason="")
