"""Repository-level tag evidence contracts shared by profile models and detection.

These helpers classify already-emitted tags and contextual evidence. They do
not mutate profile state, detection decisions, scanner outputs, final JSON, or
runtime-owned model state. Profile learning can therefore use the same evidence
contract as detection scoring without importing detection implementation APIs.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from math import isfinite
from types import MappingProxyType
from typing import Iterable, Mapping, Tuple

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.detection_observation import ObservationSourceLocation
from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_mapping_items, no_hook_text
from Virus_Scan.utils.tagging import (
    canonical_reporting_tag,
    canonical_tag_name,
    normalize_tags,
    ordered_unique_tags,
)
from Virus_Scan.detection.registries.detection_constants import (
    CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS,
    CONTEXTUAL_DANGEROUS_ANCHOR_TAGS,
)
from Virus_Scan.detection.registries.chain_registry import HIGH_RISK_BUCKETS
from Virus_Scan.detection.registries.tag_behavior_registry_defaults import TAG_TO_BEHAVIOR

_TAG_TO_BEHAVIOR = MappingProxyType(dict(TAG_TO_BEHAVIOR))
_HIGH_RISK_BUCKETS = frozenset(HIGH_RISK_BUCKETS)
_CONTEXTUAL_DANGEROUS_ANCHOR_TAGS = frozenset(CONTEXTUAL_DANGEROUS_ANCHOR_TAGS)
_TAG_EVIDENCE_EMPTY_TEXT = ""


TAG_EVIDENCE_SCHEMA_VERSION = "stage2636_10011_tag_evidence_v2"
TAG_EVIDENCE_RECORD_LIMIT = 256
TAG_EVIDENCE_PARENT_LIMIT = 32
TAG_EVIDENCE_KINDS = frozenset((
    "observed", "normalized", "derived", "composite", "suppression", "failure",
))
TAG_EVIDENCE_POLARITIES = frozenset(("positive", "negative", "neutral", "unavailable"))
TAG_EVIDENCE_SCOREABILITY_CLASSES = frozenset((
    "raw", "support", "scoreable", "composite", "suppressed", "none",
))


def _tag_evidence_token(value: object, *, default: str = "") -> tuple[str, str]:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_tag_evidence_record_text",
        unsupported_reason="unsafe_tag_evidence_record_text_rejected",
    )
    if reason:
        return default, reason
    return str.strip(text), ""


def _tag_evidence_token_tuple(value: object) -> tuple[tuple[str, ...], str]:
    if value is None:
        return (), ""
    if type(value) is str:
        values = (value,)
    elif type(value) in (tuple, list):
        values = tuple(value)
    elif type(value) in (set, frozenset):
        values = tuple(sorted(item for item in value if type(item) is str))
        if len(values) != len(value):
            return (), "tag_evidence_parent_ids_rejected"
    else:
        return (), "tag_evidence_parent_ids_rejected"
    out: list[str] = []
    seen: set[str] = set()
    for item in values[:TAG_EVIDENCE_PARENT_LIMIT]:
        text, reason = _tag_evidence_token(item)
        if reason or not text:
            return (), "tag_evidence_parent_id_rejected"
        if text not in seen:
            seen.add(text)
            out.append(text)
    return tuple(out), ""


def _tag_evidence_unit_interval(value: object, *, field_name: str) -> tuple[float, str]:
    return no_hook_finite_float(
        value,
        default=0.0,
        minimum=0.0,
        maximum=1.0,
        reason=f"tag_evidence_{field_name}_rejected",
        non_finite_reason=f"tag_evidence_{field_name}_non_finite",
        allow_exact_text=False,
    )


def deterministic_tag_evidence_id(
    *,
    root_observation_id: object,
    canonical_tag_id: object,
    evidence_kind: object,
    source_detector: object,
    source_stage: object,
    parent_evidence_ids: object = (),
    vocabulary_version: object = "",
    rule_version: object = "",
) -> str:
    """Return a deterministic evidence ID without wall-clock or process state."""
    fields: list[str] = []
    for value in (
        root_observation_id, canonical_tag_id, evidence_kind, source_detector,
        source_stage, vocabulary_version, rule_version,
    ):
        text, reason = _tag_evidence_token(value)
        fields.append("" if reason else text)
    parents, parent_reason = _tag_evidence_token_tuple(parent_evidence_ids)
    if parent_reason:
        parents = ()
    payload = "\x1f".join((*fields, *parents)).encode("utf-8", "strict")
    return "tag_ev_" + hashlib.sha256(payload).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class TagEvidenceRecord:
    """Canonical immutable tag evidence identity used by every internal model."""

    canonical_tag_id: str
    publication_name: str
    evidence_id: str
    source_detector: str
    source_stage: str
    evidence_kind: str
    parent_evidence_ids: tuple[str, ...] = ()
    confidence: float = 0.0
    support: float = 0.0
    polarity: str = "neutral"
    behavior_bucket: str = "other_behavior"
    attack_phase: str = "unknown"
    scoreability_class: str = "none"
    correlation_group: str = ""
    root_observation_id: str = ""
    vocabulary_version: str = ""
    rule_version: str = ""
    unavailable_reason: str = ""
    raw_observation_name: str = ""
    observation_id: str = ""
    modality: str = "unavailable"
    platform: str = ""
    actor_identity: str = ""
    target_identity: str = ""
    artifact_identity: str = ""
    process_identity: str = ""
    host_identity: str = ""
    connection_identity: str = ""
    source_location: ObservationSourceLocation = ObservationSourceLocation("unavailable")
    ordinal: int | None = None
    timestamp: float | None = None
    timing_provenance: str = "unavailable"
    integrity_status: str = "unavailable"
    directness: str = "unavailable"

    def __post_init__(self) -> None:
        rejection_reasons: list[str] = []
        text_fields = (
            "canonical_tag_id", "publication_name", "evidence_id", "source_detector",
            "source_stage", "evidence_kind", "polarity", "behavior_bucket",
            "attack_phase", "scoreability_class", "correlation_group",
            "root_observation_id", "vocabulary_version", "rule_version",
            "unavailable_reason", "raw_observation_name", "observation_id",
            "modality", "platform", "actor_identity", "target_identity",
            "artifact_identity", "process_identity", "host_identity",
            "connection_identity", "timing_provenance", "integrity_status",
            "directness",
        )
        values: dict[str, str] = {}
        for field_name in text_fields:
            text, reason = _tag_evidence_token(getattr(self, field_name))
            if reason:
                rejection_reasons.append(reason)
            values[field_name] = text

        canonical = canonical_tag_name(values["canonical_tag_id"])
        publication = canonical_reporting_tag(values["publication_name"] or canonical)
        kind = values["evidence_kind"]
        polarity = values["polarity"]
        scoreability = values["scoreability_class"]
        parents, parent_reason = _tag_evidence_token_tuple(self.parent_evidence_ids)
        confidence, confidence_reason = _tag_evidence_unit_interval(self.confidence, field_name="confidence")
        support, support_reason = _tag_evidence_unit_interval(self.support, field_name="support")
        rejection_reasons.extend(reason for reason in (parent_reason, confidence_reason, support_reason) if reason)

        if not canonical:
            rejection_reasons.append("tag_evidence_canonical_tag_missing")
            canonical = "tag_evidence_unavailable"
        if kind not in TAG_EVIDENCE_KINDS:
            rejection_reasons.append("tag_evidence_kind_rejected")
        if polarity not in TAG_EVIDENCE_POLARITIES:
            rejection_reasons.append("tag_evidence_polarity_rejected")
        if scoreability not in TAG_EVIDENCE_SCOREABILITY_CLASSES:
            rejection_reasons.append("tag_evidence_scoreability_rejected")
        if kind in {"normalized", "derived", "composite", "suppression"} and not parents:
            rejection_reasons.append("tag_evidence_parent_required")
        if kind == "observed" and parents:
            rejection_reasons.append("tag_evidence_observed_parent_rejected")
        root_id = values["root_observation_id"]
        if not root_id:
            rejection_reasons.append("tag_evidence_root_observation_missing")
        correlation_group = values["correlation_group"]
        if scoreability in {"scoreable", "composite"} and not correlation_group:
            rejection_reasons.append("tag_evidence_scoreable_correlation_group_missing")
        if kind == "suppression" and polarity != "negative":
            rejection_reasons.append("tag_evidence_suppression_polarity_rejected")

        unavailable_reason = values["unavailable_reason"]
        if type(self.source_location) is not ObservationSourceLocation:
            rejection_reasons.append("tag_evidence_source_location_rejected")
            source_location = ObservationSourceLocation("unavailable")
        else:
            source_location = self.source_location
        if self.ordinal is not None and (type(self.ordinal) is not int or type(self.ordinal) is bool or self.ordinal < 0):
            rejection_reasons.append("tag_evidence_ordinal_rejected")
            ordinal = None
        else:
            ordinal = self.ordinal
        if self.timestamp is not None and (
            type(self.timestamp) not in (int, float)
            or type(self.timestamp) is bool
            or not isfinite(float(self.timestamp))
        ):
            rejection_reasons.append("tag_evidence_timestamp_rejected")
            timestamp = None
        else:
            timestamp = None if self.timestamp is None else float(self.timestamp)
        physical_identity = bool(
            values["observation_id"].startswith("obs_")
            and root_id.startswith("obs_")
            and (
                values["artifact_identity"]
                or values["actor_identity"]
                or values["target_identity"]
                or values["process_identity"]
                or values["host_identity"]
                or values["connection_identity"]
                or source_location.identifies_physical_source
            )
        )
        if not physical_identity and not unavailable_reason:
            unavailable_reason = "tag_evidence_physical_identity_unavailable"
        if rejection_reasons:
            kind = "failure"
            polarity = "unavailable"
            scoreability = "none"
            confidence = 0.0
            support = 0.0
            correlation_group = ""
            unavailable_reason = unavailable_reason or rejection_reasons[0]

        evidence_id = values["evidence_id"] or deterministic_tag_evidence_id(
            root_observation_id=root_id,
            canonical_tag_id=canonical,
            evidence_kind=kind,
            source_detector=values["source_detector"],
            source_stage=values["source_stage"],
            parent_evidence_ids=parents,
            vocabulary_version=values["vocabulary_version"],
            rule_version=values["rule_version"],
        )

        object.__setattr__(self, "canonical_tag_id", canonical)
        object.__setattr__(self, "publication_name", publication or canonical)
        object.__setattr__(self, "evidence_id", evidence_id)
        object.__setattr__(self, "source_detector", values["source_detector"] or "unknown_detector")
        object.__setattr__(self, "source_stage", values["source_stage"] or "unknown_stage")
        object.__setattr__(self, "evidence_kind", kind)
        object.__setattr__(self, "parent_evidence_ids", parents)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "support", support)
        object.__setattr__(self, "polarity", polarity)
        object.__setattr__(self, "behavior_bucket", values["behavior_bucket"] or "other_behavior")
        object.__setattr__(self, "attack_phase", values["attack_phase"] or "unknown")
        object.__setattr__(self, "scoreability_class", scoreability)
        object.__setattr__(self, "correlation_group", correlation_group)
        object.__setattr__(self, "root_observation_id", root_id or evidence_id)
        object.__setattr__(self, "vocabulary_version", values["vocabulary_version"] or TAG_EVIDENCE_SCHEMA_VERSION)
        object.__setattr__(self, "rule_version", values["rule_version"] or TAG_EVIDENCE_SCHEMA_VERSION)
        object.__setattr__(self, "unavailable_reason", unavailable_reason)
        object.__setattr__(self, "raw_observation_name", values["raw_observation_name"])
        object.__setattr__(self, "observation_id", values["observation_id"])
        object.__setattr__(self, "modality", values["modality"] or "unavailable")
        object.__setattr__(self, "platform", values["platform"])
        object.__setattr__(self, "actor_identity", values["actor_identity"])
        object.__setattr__(self, "target_identity", values["target_identity"])
        object.__setattr__(self, "artifact_identity", values["artifact_identity"])
        object.__setattr__(self, "process_identity", values["process_identity"])
        object.__setattr__(self, "host_identity", values["host_identity"])
        object.__setattr__(self, "connection_identity", values["connection_identity"])
        object.__setattr__(self, "source_location", source_location)
        object.__setattr__(self, "ordinal", ordinal)
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "timing_provenance", values["timing_provenance"] or "unavailable")
        object.__setattr__(self, "integrity_status", values["integrity_status"] or "unavailable")
        object.__setattr__(self, "directness", values["directness"] or "unavailable")

    @property
    def has_physical_identity(self) -> bool:
        return bool(
            self.observation_id.startswith("obs_")
            and self.root_observation_id.startswith("obs_")
            and (
                self.artifact_identity
                or self.actor_identity
                or self.target_identity
                or self.process_identity
                or self.host_identity
                or self.connection_identity
                or self.source_location.identifies_physical_source
            )
        )

    @property
    def is_positive_scoreable(self) -> bool:
        return (
            self.polarity == "positive"
            and self.scoreability_class in {"scoreable", "composite"}
            and self.evidence_kind != "failure"
            and self.unavailable_reason == ""
            and self.has_physical_identity
            and self.directness in {"direct", "derived"}
            and self.integrity_status in {"verified", "partial", "unverified"}
        )

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": TAG_EVIDENCE_SCHEMA_VERSION,
            "canonical_tag_id": self.canonical_tag_id,
            "publication_name": self.publication_name,
            "evidence_id": self.evidence_id,
            "source_detector": self.source_detector,
            "source_stage": self.source_stage,
            "evidence_kind": self.evidence_kind,
            "parent_evidence_ids": self.parent_evidence_ids,
            "confidence": self.confidence,
            "support": self.support,
            "polarity": self.polarity,
            "behavior_bucket": self.behavior_bucket,
            "attack_phase": self.attack_phase,
            "scoreability_class": self.scoreability_class,
            "correlation_group": self.correlation_group,
            "root_observation_id": self.root_observation_id,
            "vocabulary_version": self.vocabulary_version,
            "rule_version": self.rule_version,
            "unavailable_reason": self.unavailable_reason,
            "raw_observation_name": self.raw_observation_name,
            "observation_id": self.observation_id,
            "modality": self.modality,
            "platform": self.platform,
            "actor_identity": self.actor_identity,
            "target_identity": self.target_identity,
            "artifact_identity": self.artifact_identity,
            "process_identity": self.process_identity,
            "host_identity": self.host_identity,
            "connection_identity": self.connection_identity,
            "source_location": self.source_location.to_record(),
            "ordinal": self.ordinal,
            "timestamp": self.timestamp,
            "timing_provenance": self.timing_provenance,
            "integrity_status": self.integrity_status,
            "directness": self.directness,
        }


def tag_evidence_observation_fields(
    record: TagEvidenceRecord,
    *,
    directness: str | None = None,
) -> dict[str, object]:
    """Return the canonical physical-observation projection for a child record."""
    if type(record) is not TagEvidenceRecord:
        raise TypeError("tag_evidence_observation_parent_invalid")
    return {
        "observation_id": record.observation_id,
        "modality": record.modality,
        "platform": record.platform,
        "actor_identity": record.actor_identity,
        "target_identity": record.target_identity,
        "artifact_identity": record.artifact_identity,
        "process_identity": record.process_identity,
        "host_identity": record.host_identity,
        "connection_identity": record.connection_identity,
        "source_location": record.source_location,
        "ordinal": record.ordinal,
        "timestamp": record.timestamp,
        "timing_provenance": record.timing_provenance,
        "integrity_status": record.integrity_status,
        "directness": record.directness if directness is None else directness,
    }


def tag_evidence_records(value: object) -> tuple[TagEvidenceRecord, ...]:
    """Materialize only exact canonical records; reject hostile iterables."""
    if value is None:
        return ()
    if type(value) is TagEvidenceRecord:
        values = (value,)
    elif type(value) in (tuple, list):
        values = tuple(value)
    else:
        return ()
    out: list[TagEvidenceRecord] = []
    seen: set[str] = set()
    for item in values[:TAG_EVIDENCE_RECORD_LIMIT]:
        if type(item) is not TagEvidenceRecord:
            continue
        if item.evidence_id in seen:
            continue
        seen.add(item.evidence_id)
        out.append(item)
    return tuple(out)


def active_tag_evidence_records(records: object) -> tuple[TagEvidenceRecord, ...]:
    values = tag_evidence_records(records)
    suppressed = {
        (record.root_observation_id, record.canonical_tag_id)
        for record in values
        if record.evidence_kind == "suppression" or record.polarity == "negative"
    }
    return tuple(
        record for record in values
        if record.evidence_kind != "suppression"
        and record.polarity != "negative"
        and (record.root_observation_id, record.canonical_tag_id) not in suppressed
    )


def tag_evidence_string_projection(records: object) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for record in active_tag_evidence_records(records):
        tag = record.publication_name
        if tag and tag not in seen:
            seen.add(tag)
            out.append(tag)
    return tuple(out)


def tag_evidence_summary(records: object) -> Mapping[str, object]:
    values = tag_evidence_records(records)
    active = active_tag_evidence_records(values)
    roots = {record.root_observation_id for record in active if record.evidence_kind == "observed"}
    groups = {record.correlation_group for record in active if record.correlation_group}
    scoreable_families = {record.correlation_group for record in active if record.is_positive_scoreable}
    return MappingProxyType({
        "schema_version": TAG_EVIDENCE_SCHEMA_VERSION,
        "raw_observation_count": len(roots),
        "canonical_tag_count": len(tag_evidence_string_projection(values)),
        "distinct_correlation_group_count": len(groups),
        "derived_composite_count": sum(record.evidence_kind in {"derived", "composite"} for record in values),
        "scoreable_family_count": len(scoreable_families),
        "suppressed_negative_count": sum(
            record.evidence_kind == "suppression" or record.polarity == "negative" for record in values
        ),
        "failure_count": sum(record.evidence_kind == "failure" for record in values),
    })


def scoreable_tag_evidence_records(records: object) -> tuple[TagEvidenceRecord, ...]:
    return tuple(
        record for record in active_tag_evidence_records(records)
        if record.is_positive_scoreable
    )


def distinct_scoreable_root_ids(records: object) -> frozenset[str]:
    return frozenset(
        record.root_observation_id for record in scoreable_tag_evidence_records(records)
        if record.evidence_kind in {"observed", "normalized", "derived"}
    )


def distinct_scoreable_correlation_groups(records: object) -> frozenset[str]:
    return frozenset(
        record.correlation_group for record in scoreable_tag_evidence_records(records)
        if record.evidence_kind in {"observed", "normalized", "derived"} and record.correlation_group
    )



def distinct_root_tag_evidence_records(
    records: object, *, allowed_evidence_kinds: frozenset[str],
) -> tuple[TagEvidenceRecord, ...]:
    """Select one deterministic active record per root for a declared consumer."""
    if (
        type(allowed_evidence_kinds) is not frozenset
        or not allowed_evidence_kinds
        or not allowed_evidence_kinds <= TAG_EVIDENCE_KINDS
    ):
        return ()
    rank = {"normalized": 0, "observed": 1, "composite": 2, "derived": 3}
    selected: dict[str, TagEvidenceRecord] = {}
    order: list[str] = []
    for record in active_tag_evidence_records(records):
        if record.evidence_kind not in allowed_evidence_kinds:
            continue
        root_id = record.root_observation_id
        previous = selected.get(root_id)
        if previous is None:
            selected[root_id] = record
            order.append(root_id)
        elif rank.get(record.evidence_kind, 9) < rank.get(previous.evidence_kind, 9):
            selected[root_id] = record
    return tuple(selected[root_id] for root_id in order)



def distinct_positive_root_ids_for_tags(
    records: object,
    tags: object,
    *,
    allowed_evidence_kinds: frozenset[str],
    require_scoreable: bool = False,
) -> frozenset[str]:
    """Return distinct positive evidence roots supporting any declared tag."""
    if (
        type(allowed_evidence_kinds) is not frozenset
        or not allowed_evidence_kinds
        or not allowed_evidence_kinds <= TAG_EVIDENCE_KINDS
        or type(require_scoreable) is not bool
    ):
        return frozenset()
    wanted = frozenset(
        canonical_tag_name(value) for value in ordered_unique_tags(tags)
        if canonical_tag_name(value)
    )
    if not wanted:
        return frozenset()
    return frozenset(
        record.root_observation_id
        for record in active_tag_evidence_records(records)
        if record.evidence_kind in allowed_evidence_kinds
        and record.polarity == "positive"
        and (not require_scoreable or record.is_positive_scoreable)
        and (
            canonical_tag_name(record.canonical_tag_id) in wanted
            or canonical_tag_name(record.publication_name) in wanted
        )
    )


def positive_tag_group_root_matches(
    records: object,
    groups: object,
    *,
    allowed_evidence_kinds: frozenset[str],
    require_scoreable: bool = False,
) -> tuple[tuple[str, str], ...]:
    """Return one deterministic maximum semantic-group-to-root matching.

    Each returned pair is ``(root_observation_id, matched_tag)`` for one input
    group. A root may satisfy at most one group, so aliases and derivations from
    one observation cannot manufacture multi-signal evidence.
    """
    if (
        type(allowed_evidence_kinds) is not frozenset
        or not allowed_evidence_kinds
        or not allowed_evidence_kinds <= TAG_EVIDENCE_KINDS
        or type(require_scoreable) is not bool
        or type(groups) not in (tuple, list)
    ):
        return ()
    canonical_groups: list[frozenset[str]] = []
    for group in groups[:TAG_EVIDENCE_RECORD_LIMIT]:
        if type(group) not in (tuple, list, set, frozenset):
            return ()
        options = frozenset(
            canonical_tag_name(value)
            for value in ordered_unique_tags(group)
            if canonical_tag_name(value)
        )
        if not options:
            return ()
        canonical_groups.append(options)
    if not canonical_groups:
        return ()

    active = tuple(
        record for record in active_tag_evidence_records(records)
        if record.evidence_kind in allowed_evidence_kinds
        and record.polarity == "positive"
        and (not require_scoreable or record.is_positive_scoreable)
    )
    candidates: list[tuple[tuple[str, str], ...]] = []
    for options in canonical_groups:
        per_root: dict[str, str] = {}
        for record in active:
            labels = frozenset((
                canonical_tag_name(record.canonical_tag_id),
                canonical_tag_name(record.publication_name),
            ))
            matched = sorted((labels & options) - {""})
            if matched:
                per_root.setdefault(record.root_observation_id, matched[0])
        candidates.append(tuple(sorted(per_root.items())))

    root_to_group: dict[str, int] = {}
    group_choice: dict[int, tuple[str, str]] = {}

    def assign(group_index: int, visited: set[str]) -> bool:
        for root_id, tag in candidates[group_index]:
            if root_id in visited:
                continue
            visited.add(root_id)
            previous = root_to_group.get(root_id)
            if previous is None or assign(previous, visited):
                root_to_group[root_id] = group_index
                group_choice[group_index] = (root_id, tag)
                return True
        return False

    order = sorted(range(len(candidates)), key=lambda index: (len(candidates[index]), index))
    for group_index in order:
        assign(group_index, set())
    return tuple(group_choice[index] for index in sorted(group_choice))


def positive_tag_groups_have_distinct_roots(
    records: object,
    groups: object,
    *,
    allowed_evidence_kinds: frozenset[str],
    require_scoreable: bool = False,
) -> bool:
    """Return whether every semantic group is proven by a distinct root."""
    if type(groups) not in (tuple, list) or not groups:
        return False
    matches = positive_tag_group_root_matches(
        records,
        groups,
        allowed_evidence_kinds=allowed_evidence_kinds,
        require_scoreable=require_scoreable,
    )
    return len(matches) == len(groups)


def required_positive_tags_have_distinct_roots(
    records: object, required: object, *, allowed_evidence_kinds: frozenset[str],
) -> bool:
    """Prove semantic correlation terms come from independent positive roots."""
    if (
        type(allowed_evidence_kinds) is not frozenset
        or not allowed_evidence_kinds
        or not allowed_evidence_kinds <= TAG_EVIDENCE_KINDS
    ):
        return False
    required_values = ordered_unique_tags(required)
    required_tags = tuple(
        canonical_tag_name(value) for value in required_values
        if canonical_tag_name(value)
    )
    if not required_tags:
        return False
    active = active_tag_evidence_records(records)
    used_roots: set[str] = set()
    for tag in sorted(set(required_tags)):
        candidates = tuple(
            record for record in active
            if record.evidence_kind in allowed_evidence_kinds
            and record.polarity == "positive"
            and record.canonical_tag_id == tag
            and record.root_observation_id not in used_roots
        )
        if not candidates:
            return False
        used_roots.add(candidates[0].root_observation_id)
    return True


def tag_evidence_record_from_mapping(value: object) -> TagEvidenceRecord:
    items = no_hook_mapping_items(value)
    if items is None:
        return TagEvidenceRecord(
            canonical_tag_id="tag_evidence_unavailable",
            publication_name="tag_evidence_unavailable",
            evidence_id="",
            source_detector="persistence",
            source_stage="replay",
            evidence_kind="failure",
            polarity="unavailable",
            root_observation_id="tag_evidence_replay_unavailable",
            unavailable_reason="tag_evidence_record_mapping_rejected",
        )
    data = {key: item for key, item in items if type(key) is str}
    return TagEvidenceRecord(
        canonical_tag_id=data.get("canonical_tag_id", "tag_evidence_unavailable"),
        publication_name=data.get("publication_name", ""),
        evidence_id=data.get("evidence_id", ""),
        source_detector=data.get("source_detector", "persistence"),
        source_stage=data.get("source_stage", "replay"),
        evidence_kind=data.get("evidence_kind", "failure"),
        parent_evidence_ids=data.get("parent_evidence_ids", ()),
        confidence=data.get("confidence", 0.0),
        support=data.get("support", 0.0),
        polarity=data.get("polarity", "unavailable"),
        behavior_bucket=data.get("behavior_bucket", "other_behavior"),
        attack_phase=data.get("attack_phase", "unknown"),
        scoreability_class=data.get("scoreability_class", "none"),
        correlation_group=data.get("correlation_group", ""),
        root_observation_id=data.get("root_observation_id", "tag_evidence_replay_unavailable"),
        vocabulary_version=data.get("vocabulary_version", ""),
        rule_version=data.get("rule_version", ""),
        unavailable_reason=data.get("unavailable_reason", ""),
        raw_observation_name=data.get("raw_observation_name", ""),
        observation_id=data.get("observation_id", ""),
        modality=data.get("modality", "unavailable"),
        platform=data.get("platform", ""),
        actor_identity=data.get("actor_identity", ""),
        target_identity=data.get("target_identity", ""),
        artifact_identity=data.get("artifact_identity", ""),
        process_identity=data.get("process_identity", ""),
        host_identity=data.get("host_identity", ""),
        connection_identity=data.get("connection_identity", ""),
        source_location=(
            ObservationSourceLocation.from_record(data.get("source_location"))
            if type(data.get("source_location")) is dict
            else ObservationSourceLocation("unavailable")
        ),
        ordinal=data.get("ordinal"),
        timestamp=data.get("timestamp"),
        timing_provenance=data.get("timing_provenance", "unavailable"),
        integrity_status=data.get("integrity_status", "unavailable"),
        directness=data.get("directness", "unavailable"),
    )


def safe_tag_evidence_text(value: object, replacement_text: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_tag_evidence_text",
        unsupported_reason="unsafe_tag_evidence_text_value_rejected",
    )
    if reason:
        replacement, replacement_reason = no_hook_text(
            replacement_text,
            missing_reason="missing_tag_evidence_default",
            unsupported_reason="unsafe_tag_evidence_default_rejected",
        )
        return _TAG_EVIDENCE_EMPTY_TEXT if replacement_reason else replacement
    return text


def _safe_tag_evidence_token(value: object, replacement_text: str = "") -> str:
    return str.strip(safe_tag_evidence_text(value, replacement_text))


def validation_text(blob: object) -> str:
    if type(blob) is bytes:
        return str.lower(bytes.decode(blob[:1024 * 1024], "utf-8", "ignore"))
    return str.lower(safe_tag_evidence_text(blob))


def _safe_tag_evidence_join(values: Iterable[object] | None) -> str:
    return " ".join(_safe_tag_evidence_token(item).lower() for item in ordered_unique_tags(values))


def evidence_level_for_tag(
    tag: object,
    strings_blob: object = "",
    path: object = None,
    api_calls: Iterable[object] | None = None,
    ordered_events: Iterable[object] | None = None,
) -> Tuple[str, float]:
    del path  # Explicitly unused contract parameters.
    text = validation_text(strings_blob)
    low = _safe_tag_evidence_token(tag).lower()
    if low == "":
        low = "tag_evidence_unavailable"
    api_text = _safe_tag_evidence_join(api_calls)
    events = [_safe_tag_evidence_token(e).lower() for e in ordered_unique_tags(ordered_events)]
    if low in events or any(low in e for e in events):
        return "ordered_chain", 0.85
    if api_text and (low in api_text or any(x in api_text for x in ["createprocess", "shellexecute", "writeprocessmemory", "win32_process.create"])):
        return "api_context", 0.65
    if any(x in text for x in ["subprocess", "os.system", "popen(", "createprocess", "shellexecute", "winexec", "renpy.python.py_exec_bytecode"]):
        if low in {"wmi_exec", "wmic_exec", "win32_process_create", "powershell_exec", "cmd_exec", "process_exec"}:
            return "reachable_exec", 0.78
        return "api_context", 0.58
    if any(x in text for x in ["base64", "fromcharcode", "xor", "decode", "gzip", "zlib"]):
        return "decoded_string", 0.35
    return "weak_string", 0.15


def _anchor_behavior_bucket(tag: object) -> str:
    key = _safe_tag_evidence_token(tag).lower()
    return _safe_tag_evidence_token(_TAG_TO_BEHAVIOR.get(key, "other_behavior"), "other_behavior").lower()


def dangerous_anchor_learning_block_enabled() -> bool:
    """Return the canonical immutable dangerous-anchor learning policy."""
    return CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS is True


def contextual_dangerous_anchor_hits(tags: Iterable[object] | None) -> list[str]:
    """Return normalized dangerous anchors present in a tag set.

    Errors produce explicit failure evidence tags rather than a silent empty
    result, because an empty result can incorrectly admit unsafe profile
    learning.
    """
    try:
        norm = normalize_tags(tags)
    except RECOVERABLE_RUNTIME_ERRORS:
        norm = ["contextual_dangerous_anchor_failure"]
    tagset = {text.lower() for t in norm for text in (_safe_tag_evidence_token(t),) if text != ""}
    hits = set(tagset & _CONTEXTUAL_DANGEROUS_ANCHOR_TAGS)
    try:
        for tag in tagset:
            if _anchor_behavior_bucket(tag) in _HIGH_RISK_BUCKETS:
                hits.add(tag)
    except RECOVERABLE_RUNTIME_ERRORS:
        hits.add("contextual_dangerous_anchor_failure")
    return sorted(hits)


__all__ = (
    "TAG_EVIDENCE_KINDS",
    "TAG_EVIDENCE_POLARITIES",
    "TAG_EVIDENCE_RECORD_LIMIT",
    "TAG_EVIDENCE_SCHEMA_VERSION",
    "TAG_EVIDENCE_SCOREABILITY_CLASSES",
    "TagEvidenceRecord",
    "active_tag_evidence_records",
    "contextual_dangerous_anchor_hits",
    "dangerous_anchor_learning_block_enabled",
    "deterministic_tag_evidence_id",
    "distinct_positive_root_ids_for_tags",
    "distinct_root_tag_evidence_records",
    "distinct_scoreable_correlation_groups",
    "distinct_scoreable_root_ids",
    "evidence_level_for_tag",
    "positive_tag_group_root_matches",
    "positive_tag_groups_have_distinct_roots",
    "required_positive_tags_have_distinct_roots",
    "safe_tag_evidence_text",
    "scoreable_tag_evidence_records",
    "tag_evidence_observation_fields",
    "tag_evidence_record_from_mapping",
    "tag_evidence_records",
    "tag_evidence_string_projection",
    "tag_evidence_summary",
    "validation_text",
)
