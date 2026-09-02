"""Canonical immutable artifact-evidence authority for one evidence generation.

The snapshot contains only physical evidence and deterministic derivations rooted
in physical evidence.  Model/context projections, generator intent, external
corroboration, and ATT&CK decisions are deliberately outside this contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from Virus_Scan.contracts.artifact_read_snapshot import ArtifactReadSnapshot
from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.detection_observation import DetectionObservation
from Virus_Scan.contracts.static_program_analysis import StaticProgramAnalysis
from Virus_Scan.contracts.yara_hits import YaraScanResult
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence

ARTIFACT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION = (
    "stage2636_11020_artifact_evidence_snapshot_v1"
)
DETERMINISTIC_EVIDENCE_DERIVATION_SCHEMA_VERSION = (
    "stage2636_11020_deterministic_evidence_derivation_v1"
)
ARTIFACT_EVIDENCE_COMPLETENESS_STATES = frozenset({
    "complete", "partial", "unavailable",
})
_MAX_ITEMS = 4096
_MAX_TEXT = 512
_HEX = frozenset("0123456789abcdef")


def _text(value: object, reason: str, *, maximum: int = _MAX_TEXT) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value).strip()
    if not text or len(text) > maximum:
        raise ValueError(reason)
    return text


def _optional_text(value: object, reason: str, *, maximum: int = _MAX_TEXT) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value).strip()
    if len(text) > maximum:
        raise ValueError(reason)
    return text


def _digest(value: object, reason: str, *, allow_blank: bool = False) -> str:
    text = _optional_text(value, reason, maximum=64).lower()
    if allow_blank and text == "":
        return ""
    if len(text) != 64 or any(character not in _HEX for character in text):
        raise ValueError(reason)
    return text


def _identity_tuple(
    value: object,
    reason: str,
    *,
    prefix: str | None = None,
    maximum: int = _MAX_ITEMS,
) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > maximum:
        raise TypeError(reason)
    items: list[str] = []
    for raw in value:
        text = _text(raw, reason, maximum=256)
        if prefix is not None and not text.startswith(prefix):
            raise ValueError(reason)
        items.append(text)
    ordered = tuple(sorted(set(items)))
    if len(ordered) != len(items):
        raise ValueError(reason + "_duplicate")
    return ordered


@dataclass(frozen=True, slots=True, order=True)
class DeterministicEvidenceDerivation:
    """One deterministic derivation whose authority is rooted in physical facts."""

    derivation_id: str
    derivation_kind: str
    producer_id: str
    producer_version: str
    source_root_ids: tuple[str, ...]
    output_evidence_ids: tuple[str, ...]
    parent_evidence_ids: tuple[str, ...] = ()
    schema_version: str = DETERMINISTIC_EVIDENCE_DERIVATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not DeterministicEvidenceDerivation:
            raise TypeError("deterministic_derivation_owner_invalid")
        derivation_id = _text(
            self.derivation_id, "deterministic_derivation_id_invalid", maximum=128,
        )
        if not derivation_id.startswith("deriv_"):
            raise ValueError("deterministic_derivation_id_invalid")
        kind = _text(
            self.derivation_kind, "deterministic_derivation_kind_invalid", maximum=128,
        )
        producer = _text(
            self.producer_id, "deterministic_derivation_producer_invalid", maximum=256,
        )
        version = _text(
            self.producer_version,
            "deterministic_derivation_producer_version_invalid",
            maximum=128,
        )
        roots = _identity_tuple(
            self.source_root_ids,
            "deterministic_derivation_source_roots_invalid",
            prefix="obs_",
        )
        if not roots:
            raise ValueError("deterministic_derivation_source_roots_required")
        outputs = _identity_tuple(
            self.output_evidence_ids,
            "deterministic_derivation_outputs_invalid",
        )
        if not outputs:
            raise ValueError("deterministic_derivation_outputs_required")
        parents = _identity_tuple(
            self.parent_evidence_ids,
            "deterministic_derivation_parents_invalid",
        )
        if self.schema_version != DETERMINISTIC_EVIDENCE_DERIVATION_SCHEMA_VERSION:
            raise ValueError("deterministic_derivation_schema_invalid")
        object.__setattr__(self, "derivation_id", derivation_id)
        object.__setattr__(self, "derivation_kind", kind)
        object.__setattr__(self, "producer_id", producer)
        object.__setattr__(self, "producer_version", version)
        object.__setattr__(self, "source_root_ids", roots)
        object.__setattr__(self, "output_evidence_ids", outputs)
        object.__setattr__(self, "parent_evidence_ids", parents)

    def to_record(self) -> dict[str, object]:
        return {
            "derivation_id": self.derivation_id,
            "derivation_kind": self.derivation_kind,
            "output_evidence_ids": self.output_evidence_ids,
            "parent_evidence_ids": self.parent_evidence_ids,
            "producer_id": self.producer_id,
            "producer_version": self.producer_version,
            "schema_version": self.schema_version,
            "source_root_ids": self.source_root_ids,
        }


def _static_analyses(value: object) -> tuple[StaticProgramAnalysis, ...]:
    if type(value) is not tuple or len(value) > 256:
        raise TypeError("artifact_evidence_static_analyses_invalid")
    if any(type(item) is not StaticProgramAnalysis for item in value):
        raise TypeError("artifact_evidence_static_analysis_owner_invalid")
    ordered = tuple(sorted(value, key=lambda item: (item.language, item.semantic_digest)))
    identities = tuple((item.language, item.semantic_digest) for item in ordered)
    if len(set(identities)) != len(identities):
        raise ValueError("artifact_evidence_static_analysis_duplicate")
    return ordered


def _physical_observations(value: object) -> tuple[DetectionObservation, ...]:
    if type(value) is not tuple or len(value) > _MAX_ITEMS:
        raise TypeError("artifact_evidence_physical_observations_invalid")
    if any(type(item) is not DetectionObservation for item in value):
        raise TypeError("artifact_evidence_physical_observation_owner_invalid")
    ordered = tuple(sorted(value, key=lambda item: item.observation_id))
    ids = tuple(item.observation_id for item in ordered)
    if len(set(ids)) != len(ids):
        raise ValueError("artifact_evidence_physical_observation_duplicate")
    return ordered


def _limitations(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > 512:
        raise TypeError("artifact_evidence_limitations_invalid")
    items = tuple(_text(item, "artifact_evidence_limitation_invalid") for item in value)
    ordered = tuple(sorted(set(items)))
    if len(ordered) != len(items):
        raise ValueError("artifact_evidence_limitation_duplicate")
    return ordered


def _derivations(value: object) -> tuple[DeterministicEvidenceDerivation, ...]:
    if type(value) is not tuple or len(value) > _MAX_ITEMS:
        raise TypeError("artifact_evidence_derivations_invalid")
    if any(type(item) is not DeterministicEvidenceDerivation for item in value):
        raise TypeError("artifact_evidence_derivation_owner_invalid")
    ordered = tuple(sorted(value, key=lambda item: item.derivation_id))
    if len({item.derivation_id for item in ordered}) != len(ordered):
        raise ValueError("artifact_evidence_derivation_duplicate")
    return ordered


def _physical_roots(
    observations: Iterable[DetectionObservation],
    yara_result: YaraScanResult,
) -> tuple[str, ...]:
    roots = {
        item.root_observation_id
        for item in observations
        if item.root_observation_id.startswith("obs_")
    }
    roots.update(
        item.root_observation_id
        for item in yara_result.hits
        if item.root_observation_id.startswith("obs_")
    )
    return tuple(sorted(roots))


@dataclass(frozen=True, slots=True)
class ArtifactEvidenceSnapshot:
    """One final immutable artifact-evidence generation.

    This contract is deliberately incapable of holding model/context evidence,
    generator intent, external corroboration, or an ATT&CK mapping result.
    """

    artifact_read_snapshot: ArtifactReadSnapshot
    physical_observations: tuple[DetectionObservation, ...]
    static_program_analyses: tuple[StaticProgramAnalysis, ...]
    yara_scan_result: YaraScanResult
    tag_evidence: TagEvidence
    chain_evidence: ChainEvidence
    parser_analysis_limitations: tuple[str, ...]
    evidence_completeness: str
    deterministic_derivations: tuple[DeterministicEvidenceDerivation, ...] = ()
    physical_root_ids: tuple[str, ...] = field(default_factory=tuple, init=False)
    semantic_digest: str = ""
    schema_version: str = ARTIFACT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ArtifactEvidenceSnapshot:
            raise TypeError("artifact_evidence_snapshot_owner_invalid")
        if type(self.artifact_read_snapshot) is not ArtifactReadSnapshot:
            raise TypeError("artifact_evidence_artifact_read_snapshot_required")
        observations = _physical_observations(self.physical_observations)
        analyses = _static_analyses(self.static_program_analyses)
        if type(self.yara_scan_result) is not YaraScanResult:
            raise TypeError("artifact_evidence_yara_scan_result_required")
        if type(self.tag_evidence) is not TagEvidence:
            raise TypeError("artifact_evidence_tag_evidence_required")
        if type(self.chain_evidence) is not ChainEvidence:
            raise TypeError("artifact_evidence_chain_evidence_required")
        limitations = _limitations(self.parser_analysis_limitations)
        completeness = _text(
            self.evidence_completeness,
            "artifact_evidence_completeness_invalid",
            maximum=32,
        ).lower()
        if completeness not in ARTIFACT_EVIDENCE_COMPLETENESS_STATES:
            raise ValueError("artifact_evidence_completeness_invalid")
        derivations = _derivations(self.deterministic_derivations)
        roots = _physical_roots(observations, self.yara_scan_result)
        root_set = set(roots)

        read_snapshot = self.artifact_read_snapshot
        if read_snapshot.complete:
            for analysis in analyses:
                if (
                    analysis.content_sha256 != read_snapshot.content_sha256
                    or analysis.content_size != read_snapshot.size
                ):
                    raise ValueError("artifact_evidence_static_analysis_content_mismatch")
        elif completeness != "unavailable":
            raise ValueError("artifact_evidence_unreadable_completeness_invalid")

        if completeness == "unavailable" and (
            observations or analyses or self.yara_scan_result.hits
            or self.tag_evidence.records or self.chain_evidence.decisions or derivations
        ):
            raise ValueError("artifact_evidence_unavailable_positive_evidence_invalid")

        for record in self.tag_evidence.records:
            if record.root_observation_id not in root_set:
                raise ValueError("artifact_evidence_tag_root_not_physical")
        if not set(self.chain_evidence.scoreable_root_ids).issubset(root_set):
            raise ValueError("artifact_evidence_chain_root_not_physical")
        for derivation in derivations:
            if not set(derivation.source_root_ids).issubset(root_set):
                raise ValueError("artifact_evidence_derivation_root_not_physical")

        object.__setattr__(self, "physical_observations", observations)
        object.__setattr__(self, "static_program_analyses", analyses)
        object.__setattr__(self, "parser_analysis_limitations", limitations)
        object.__setattr__(self, "evidence_completeness", completeness)
        object.__setattr__(self, "deterministic_derivations", derivations)
        object.__setattr__(self, "physical_root_ids", roots)
        if self.schema_version != ARTIFACT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("artifact_evidence_snapshot_schema_invalid")
        computed = canonical_json_sha256(self._semantic_record())
        supplied = _digest(
            self.semantic_digest,
            "artifact_evidence_semantic_digest_invalid",
            allow_blank=True,
        )
        if supplied not in ("", computed):
            raise ValueError("artifact_evidence_semantic_digest_mismatch")
        object.__setattr__(self, "semantic_digest", computed)

    def _semantic_record(self) -> dict[str, object]:
        return {
            "artifact_read_snapshot": self.artifact_read_snapshot.to_record(),
            "chain_evidence": self.chain_evidence.to_record(decision_limit=256),
            "deterministic_derivations": tuple(
                item.to_record() for item in self.deterministic_derivations
            ),
            "evidence_completeness": self.evidence_completeness,
            "parser_analysis_limitations": self.parser_analysis_limitations,
            "physical_observations": tuple(
                item.to_record() for item in self.physical_observations
            ),
            "physical_root_ids": self.physical_root_ids,
            "schema_version": self.schema_version,
            "static_program_analyses": tuple(
                item.to_record() for item in self.static_program_analyses
            ),
            "tag_evidence": self.tag_evidence.to_record(record_limit=256),
            "yara_scan_result": self.yara_scan_result.to_record(),
        }

    @property
    def content_sha256(self) -> str:
        return self.artifact_read_snapshot.content_sha256

    @property
    def artifact_identity(self) -> str:
        if not self.content_sha256:
            return ""
        return "content_sha256:" + self.content_sha256

    def to_record(self) -> dict[str, object]:
        record = self._semantic_record()
        record["semantic_digest"] = self.semantic_digest
        record["evidence_authority"] = "physical_and_deterministic_only"
        return record


__all__ = (
    "ARTIFACT_EVIDENCE_COMPLETENESS_STATES",
    "ARTIFACT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION",
    "DETERMINISTIC_EVIDENCE_DERIVATION_SCHEMA_VERSION",
    "ArtifactEvidenceSnapshot",
    "DeterministicEvidenceDerivation",
)
