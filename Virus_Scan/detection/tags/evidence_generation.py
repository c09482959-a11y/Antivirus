"""Canonical immutable TagEvidence input and finalization generations.

Scanner stages append normalized physical evidence to an unfinalized input bundle.
Only this owner advances that bundle through the canonical finalization policy.
"""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.tags.heuristics.finalization import (
    _finalize_tag_evidence_for_path,
    validate_tag_evidence_input_for_path,
)

TAG_EVIDENCE_GENERATION_SCHEMA_VERSION = "stage2636_11020_tag_evidence_generation_v1"


def _generation_text(value: object, *, default: str) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="tag_evidence_generation_text_missing",
        unsupported_reason="tag_evidence_generation_text_rejected",
    )
    text = str.strip(text)
    return default if reason or not text else text


def _record_ids(evidence: TagEvidence) -> tuple[str, ...]:
    return tuple(record.evidence_id for record in evidence.records)


def _input_evidence_digest(evidence: TagEvidence) -> str:
    """Bind generation identity to canonical physical records only.

    Bundle ``reasons`` describe the construction/projection boundary and may
    legitimately change when the same immutable records are merged again.
    They are not physical evidence identity and therefore must not create a
    new evidence generation.
    """
    return canonical_json_sha256({
        "schema_version": TAG_EVIDENCE_GENERATION_SCHEMA_VERSION,
        "records": tuple(record.to_record() for record in evidence.records),
    })


def _final_evidence_digest(evidence: TagEvidence) -> str:
    return canonical_json_sha256(evidence.to_record(record_limit=256))


def _context_digest(*, path: object, strings_blob: object) -> str:
    path_text = str.__str__(path) if type(path) is str else ""
    blob_text = str.__str__(strings_blob) if type(strings_blob) is str else ""
    return canonical_json_sha256({"path": path_text, "strings_blob": blob_text})


def merge_tag_evidence_inputs(values: object) -> TagEvidence:
    """Merge exact immutable evidence bundles without running finalization."""
    if type(values) not in (tuple, list):
        raise TypeError("tag_evidence_input_sequence_required")
    records = tuple(
        record
        for value in values
        if type(value) is TagEvidence
        for record in value.records
    )
    return TagEvidence.from_records(records, reasons={
        "generation_schema_version": TAG_EVIDENCE_GENERATION_SCHEMA_VERSION,
        "input_bundle_count": sum(type(value) is TagEvidence for value in values),
    })


@dataclass(frozen=True, slots=True)
class TagEvidenceGeneration:
    """One finalized evidence generation with exact input/reuse lineage."""

    generation_index: int
    generation_id: str
    parent_generation_id: str
    source: str
    context_digest: str
    input_digest: str
    evidence_digest: str
    input_evidence: TagEvidence
    evidence: TagEvidence
    added_evidence_ids: tuple[str, ...]
    reused_evidence_ids: tuple[str, ...]
    finalization_count: int = 1

    def __post_init__(self) -> None:
        if type(self.generation_index) is not int or type(self.generation_index) is bool or self.generation_index < 0:
            raise ValueError("tag_evidence_generation_index_invalid")
        if type(self.input_evidence) is not TagEvidence or type(self.evidence) is not TagEvidence:
            raise TypeError("tag_evidence_generation_bundle_invalid")
        if type(self.finalization_count) is not int or self.finalization_count != 1:
            raise ValueError("tag_evidence_generation_finalization_count_invalid")
        for value, label in (
            (self.generation_id, "generation_id"),
            (self.context_digest, "context_digest"),
            (self.input_digest, "input_digest"),
            (self.evidence_digest, "evidence_digest"),
        ):
            if type(value) is not str or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError("tag_evidence_generation_" + label + "_invalid")
        if self.parent_generation_id and (
            type(self.parent_generation_id) is not str
            or len(self.parent_generation_id) != 64
            or any(ch not in "0123456789abcdef" for ch in self.parent_generation_id)
        ):
            raise ValueError("tag_evidence_generation_parent_id_invalid")
        input_ids = set(_record_ids(self.input_evidence))
        added = tuple(dict.fromkeys(self.added_evidence_ids))
        reused = tuple(dict.fromkeys(self.reused_evidence_ids))
        if set(added) & set(reused) or set(added) | set(reused) != input_ids:
            raise ValueError("tag_evidence_generation_input_ledger_invalid")
        object.__setattr__(self, "source", _generation_text(self.source, default="tag_evidence_generation"))
        object.__setattr__(self, "added_evidence_ids", added)
        object.__setattr__(self, "reused_evidence_ids", reused)

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": TAG_EVIDENCE_GENERATION_SCHEMA_VERSION,
            "added_evidence_ids": self.added_evidence_ids,
            "context_digest": self.context_digest,
            "evidence_digest": self.evidence_digest,
            "finalization_count": self.finalization_count,
            "generation_id": self.generation_id,
            "generation_index": self.generation_index,
            "input_digest": self.input_digest,
            "parent_generation_id": self.parent_generation_id,
            "reused_evidence_ids": self.reused_evidence_ids,
            "source": self.source,
        }


def finalize_tag_evidence_generation(
    inputs: object,
    *,
    path: object = None,
    strings_blob: object = "",
    source: object = "",
    previous_generation: TagEvidenceGeneration | None = None,
) -> TagEvidenceGeneration:
    """Finalize exactly one changed immutable input generation.

    An unchanged input/context returns the existing generation and performs no
    finalization. Callers therefore cannot accidentally rebuild unchanged
    TagEvidence merely because a downstream stage reuses it.
    """
    if previous_generation is not None and type(previous_generation) is not TagEvidenceGeneration:
        raise TypeError("tag_evidence_previous_generation_invalid")
    if type(inputs) is TagEvidence:
        additions = inputs
    elif (
        type(inputs) in (tuple, list)
        and bool(inputs)
        and all(type(item) is TagEvidence for item in inputs)
    ):
        additions = merge_tag_evidence_inputs(inputs)
    else:
        additions = validate_tag_evidence_input_for_path(
            inputs, path=path, strings_blob=strings_blob, source=source,
        )

    if previous_generation is None:
        input_evidence = additions
    else:
        input_evidence = merge_tag_evidence_inputs((previous_generation.input_evidence, additions))

    input_digest = _input_evidence_digest(input_evidence)
    context_digest = _context_digest(path=path, strings_blob=strings_blob)
    if (
        previous_generation is not None
        and previous_generation.input_digest == input_digest
        and previous_generation.context_digest == context_digest
    ):
        return previous_generation

    source_name = _generation_text(source, default="tag_evidence_generation")
    evidence = _finalize_tag_evidence_for_path(
        input_evidence,
        path=path,
        strings_blob=strings_blob,
        source=source_name,
    )
    prior_ids = set() if previous_generation is None else set(_record_ids(previous_generation.input_evidence))
    current_ids = _record_ids(input_evidence)
    added_ids = tuple(item for item in current_ids if item not in prior_ids)
    reused_ids = tuple(item for item in current_ids if item in prior_ids)
    evidence_digest = _final_evidence_digest(evidence)
    generation_index = 0 if previous_generation is None else previous_generation.generation_index + 1
    parent_id = "" if previous_generation is None else previous_generation.generation_id
    generation_id = canonical_json_sha256({
        "schema_version": TAG_EVIDENCE_GENERATION_SCHEMA_VERSION,
        "context_digest": context_digest,
        "evidence_digest": evidence_digest,
        "generation_index": generation_index,
        "input_digest": input_digest,
        "parent_generation_id": parent_id,
    })
    return TagEvidenceGeneration(
        generation_index=generation_index,
        generation_id=generation_id,
        parent_generation_id=parent_id,
        source=source_name,
        context_digest=context_digest,
        input_digest=input_digest,
        evidence_digest=evidence_digest,
        input_evidence=input_evidence,
        evidence=evidence,
        added_evidence_ids=added_ids,
        reused_evidence_ids=reused_ids,
    )


__all__ = (
    "TAG_EVIDENCE_GENERATION_SCHEMA_VERSION",
    "TagEvidenceGeneration",
    "finalize_tag_evidence_generation",
    "merge_tag_evidence_inputs",
)
