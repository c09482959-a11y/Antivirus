"""Immutable chain and canonical tag evidence outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.contracts.tag_evidence import (
    TAG_EVIDENCE_SCHEMA_VERSION,
    TagEvidenceRecord,
    tag_evidence_record_from_mapping,
    tag_evidence_records,
    tag_evidence_string_projection,
    tag_evidence_summary,
)
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.detection.models.stage_value_utils import freeze_mapping_or_empty, frozen_tuple_or_empty


@dataclass(frozen=True)
class ChainEvidence:
    """Chain matches and reasoning only."""

    chains: tuple[object, ...]
    reasoning: tuple[object, ...]

    def __post_init__(self) -> None:
        """Deep-freeze direct chain evidence constructor values."""
        object.__setattr__(self, "chains", frozen_tuple_or_empty(self.chains))
        object.__setattr__(self, "reasoning", frozen_tuple_or_empty(self.reasoning))


@dataclass(frozen=True)
class TagEvidence:
    """Canonical immutable tag-evidence bundle and publication projection."""

    tags: tuple[object, ...] = field(default_factory=tuple)
    reasons: Mapping[str, object] = field(default_factory=dict)
    records: tuple[TagEvidenceRecord, ...] = field(default_factory=tuple)
    summary: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Freeze the bundle; canonical records own projection when present."""
        records = tag_evidence_records(self.records)
        if records:
            tags = tag_evidence_string_projection(records)
            summary = tag_evidence_summary(records)
        else:
            tags = frozen_tuple_or_empty(self.tags)
            summary = freeze_mapping_or_empty(self.summary)
        object.__setattr__(self, "records", records)
        object.__setattr__(self, "tags", tags)
        object.__setattr__(self, "reasons", freeze_mapping_or_empty(self.reasons))
        object.__setattr__(self, "summary", summary)

    @classmethod
    def from_records(
        cls,
        records: object,
        *,
        reasons: Mapping[str, object] | None = None,
    ) -> "TagEvidence":
        """Construct the canonical bundle from record evidence only."""
        canonical_records = tag_evidence_records(records)
        return cls(
            tags=tag_evidence_string_projection(canonical_records),
            reasons={} if reasons is None else reasons,
            records=canonical_records,
            summary=tag_evidence_summary(canonical_records),
        )

    @classmethod
    def from_record(cls, value: object) -> "TagEvidence":
        """Restore one canonical replay bundle from its published record.

        The record boundary accepts only owned mappings and exact built-in
        record sequences. Malformed or version-mismatched state is converted to
        explicit unavailable evidence and can never become positive confidence.
        """
        items = no_hook_mapping_items(value)
        if items is None:
            return cls(
                reasons={"unavailable_reason": "tag_evidence_bundle_mapping_rejected"},
            )
        data = {key: item for key, item in items if type(key) is str}
        if data.get("schema_version") != TAG_EVIDENCE_SCHEMA_VERSION:
            return cls(
                reasons={"unavailable_reason": "tag_evidence_schema_version_rejected"},
            )
        raw_records = data.get("records", ())
        if type(raw_records) not in (tuple, list):
            return cls(
                reasons={"unavailable_reason": "tag_evidence_record_sequence_rejected"},
            )
        records = tuple(
            tag_evidence_record_from_mapping(item)
            for item in tuple(raw_records)[:256]
        )
        reasons_value = data.get("reasons", {})
        reasons_items = no_hook_mapping_items(reasons_value)
        reasons = (
            {key: item for key, item in reasons_items if type(key) is str}
            if reasons_items is not None
            else {"unavailable_reason": "tag_evidence_reasons_mapping_rejected"}
        )
        return cls.from_records(records, reasons=reasons)

    def __len__(self) -> int:
        """Return deterministic publication cardinality for bounded consumers."""
        return len(self.tags)

    def to_record(self, *, record_limit: int = 200) -> dict[str, object]:
        limit = record_limit if type(record_limit) is int and type(record_limit) is not bool else 200
        limit = max(0, min(limit, 256))
        return {
            "schema_version": TAG_EVIDENCE_SCHEMA_VERSION,
            "tags": tuple(self.tags),
            "records": tuple(record.to_record() for record in self.records[:limit]),
            "summary": dict(self.summary),
            "reasons": dict(self.reasons),
        }


__all__ = ("ChainEvidence", "TagEvidence")
