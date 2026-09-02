"""Canonical physical detection-observation contracts.

A detection observation identifies one physical scanner fact.  Tags are factual
projections of that fact and are deliberately excluded from observation-ID
material so aliases or derived tags cannot manufacture independent roots.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
from math import isfinite
from types import MappingProxyType
from typing import Mapping


DETECTION_OBSERVATION_SCHEMA_VERSION = "stage2636_10014_detection_observation_v3"
DETECTION_OBSERVATION_UNAVAILABLE_TAG = "detection_observation_unavailable"
DETECTION_OBSERVATION_MODALITIES = frozenset({
    "static_string",
    "static_structure",
    "static_control_flow",
    "dynamic_runtime",
    "host_telemetry",
    "network_telemetry",
    "yara_match",
    "metadata",
    "derived",
    "unavailable",
})
DETECTION_OBSERVATION_INTEGRITY_STATES = frozenset({
    "verified",
    "partial",
    "unverified",
    "unavailable",
})
DETECTION_OBSERVATION_DIRECTNESS = frozenset({
    "direct",
    "derived",
    "context",
    "unavailable",
})
_MAX_TEXT = 4096
_MAX_EVIDENCE_ITEMS = 128
_MAX_EVIDENCE_DEPTH = 6
_MAX_OBSERVATIONS = 4096


def _observation_text(
    value: object,
    reason: str,
    *,
    maximum: int = _MAX_TEXT,
    allow_blank: bool = False,
) -> str:
    if type(value) is str:
        text = str.__str__(value)
        within_bound = len(text) <= maximum
        blank_allowed = allow_blank or text != ""
        if within_bound and blank_allowed:
            return text
        raise ValueError(reason)
    raise TypeError(reason)


def _optional_observation_text(value: object, reason: str, *, maximum: int = _MAX_TEXT) -> str:
    return _observation_text(value, reason, maximum=maximum, allow_blank=True)


def _optional_int(value: object, reason: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or type(value) is bool:
        raise TypeError(reason)
    if value < 0 or value > 2**63 - 1:
        raise ValueError(reason)
    return value


def _optional_float(value: object, reason: str) -> float | None:
    if value is None:
        return None
    if type(value) not in (int, float) or type(value) is bool:
        raise TypeError(reason)
    number = float(value)
    if not isfinite(number):
        raise ValueError(reason)
    return number


def _confidence(value: object) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise TypeError("detection_observation_confidence_invalid")
    number = float(value)
    if not isfinite(number) or number < 0.0 or number > 1.0:
        raise ValueError("detection_observation_confidence_invalid")
    return number


def _freeze_evidence(value: object, *, depth: int = 0) -> object:
    if depth > _MAX_EVIDENCE_DEPTH:
        raise ValueError("detection_observation_evidence_depth_exceeded")
    if value is None or type(value) in (str, int, float, bool):
        if type(value) is float and not isfinite(value):
            raise ValueError("detection_observation_evidence_nonfinite")
        return value
    if type(value) is tuple:
        if len(value) > _MAX_EVIDENCE_ITEMS:
            raise ValueError("detection_observation_evidence_items_exceeded")
        return tuple(_freeze_evidence(item, depth=depth + 1) for item in value)
    if type(value) is list:
        if len(value) > _MAX_EVIDENCE_ITEMS:
            raise ValueError("detection_observation_evidence_items_exceeded")
        return tuple(_freeze_evidence(item, depth=depth + 1) for item in value)
    if type(value) is dict:
        if len(value) > _MAX_EVIDENCE_ITEMS:
            raise ValueError("detection_observation_evidence_items_exceeded")
        frozen: dict[str, object] = {}
        for key, item in dict.items(value):
            key_text = _observation_text(
                key,
                "detection_observation_evidence_key_invalid",
                maximum=256,
            )
            if key_text in frozen:
                raise ValueError("detection_observation_evidence_key_duplicate")
            frozen[key_text] = _freeze_evidence(item, depth=depth + 1)
        return MappingProxyType(dict(sorted(frozen.items())))
    raise TypeError("detection_observation_evidence_value_invalid")


def _materialize_evidence(value: object) -> object:
    if type(value) is MappingProxyType:
        return {
            key: _materialize_evidence(item)
            for key, item in value.items()
        }
    if type(value) is tuple:
        return tuple(_materialize_evidence(item) for item in value)
    return value


@dataclass(frozen=True, slots=True, order=True)
class ObservationSourceLocation:
    """Bounded structured physical source location."""

    location_type: str
    locator: str = ""
    archive_member: str = ""
    byte_offset: int | None = None
    byte_length: int | None = None
    event_id: str = ""

    def __post_init__(self) -> None:
        if type(self) is not ObservationSourceLocation:
            raise TypeError("detection_observation_location_owner_invalid")
        object.__setattr__(self, "location_type", _observation_text(
            self.location_type,
            "detection_observation_location_type_invalid",
            maximum=64,
        ))
        object.__setattr__(self, "locator", _optional_observation_text(
            self.locator,
            "detection_observation_locator_invalid",
        ))
        object.__setattr__(self, "archive_member", _optional_observation_text(
            self.archive_member,
            "detection_observation_archive_member_invalid",
        ))
        object.__setattr__(self, "byte_offset", _optional_int(
            self.byte_offset,
            "detection_observation_byte_offset_invalid",
        ))
        object.__setattr__(self, "byte_length", _optional_int(
            self.byte_length,
            "detection_observation_byte_length_invalid",
        ))
        object.__setattr__(self, "event_id", _optional_observation_text(
            self.event_id,
            "detection_observation_event_id_invalid",
            maximum=512,
        ))

    @property
    def identifies_physical_source(self) -> bool:
        return bool(
            self.locator
            or self.archive_member
            or self.byte_offset is not None
            or self.byte_length is not None
            or self.event_id
        )

    def to_record(self) -> dict[str, object]:
        return {
            "location_type": self.location_type,
            "locator": self.locator,
            "archive_member": self.archive_member,
            "byte_offset": self.byte_offset,
            "byte_length": self.byte_length,
            "event_id": self.event_id,
        }

    @classmethod
    def from_record(cls, value: object) -> "ObservationSourceLocation":
        if type(value) is not dict:
            raise TypeError("detection_observation_location_mapping_invalid")
        expected = {
            "location_type", "locator", "archive_member", "byte_offset",
            "byte_length", "event_id",
        }
        if set(value) != expected:
            raise ValueError("detection_observation_location_fields_invalid")
        return cls(
            location_type=dict.get(value, "location_type"),
            locator=dict.get(value, "locator"),
            archive_member=dict.get(value, "archive_member"),
            byte_offset=dict.get(value, "byte_offset"),
            byte_length=dict.get(value, "byte_length"),
            event_id=dict.get(value, "event_id"),
        )


def _identity_record(
    *,
    producer_id: str,
    stage_id: str,
    modality: str,
    platform: str,
    actor_identity: str,
    target_identity: str,
    artifact_identity: str,
    process_identity: str,
    host_identity: str,
    connection_identity: str,
    source_location: ObservationSourceLocation,
    ordinal: int | None,
    timestamp: float | None,
) -> dict[str, object]:
    return {
        "producer_id": producer_id,
        "stage_id": stage_id,
        "modality": modality,
        "platform": platform,
        "actor_identity": actor_identity,
        "target_identity": target_identity,
        "artifact_identity": artifact_identity,
        "process_identity": process_identity,
        "host_identity": host_identity,
        "connection_identity": connection_identity,
        "source_location": source_location.to_record(),
        "ordinal": ordinal,
        "timestamp": timestamp,
    }


def _physical_identity_record(
    *,
    actor_identity: str,
    target_identity: str,
    artifact_identity: str,
    process_identity: str,
    host_identity: str,
    connection_identity: str,
    source_location: ObservationSourceLocation,
    ordinal: int | None,
    timestamp: float | None,
) -> dict[str, object]:
    return {
        "actor_identity": actor_identity,
        "target_identity": target_identity,
        "artifact_identity": artifact_identity,
        "process_identity": process_identity,
        "host_identity": host_identity,
        "connection_identity": connection_identity,
        "source_location": source_location.to_record(),
        "ordinal": ordinal,
        "timestamp": timestamp,
    }


def deterministic_physical_root_id(
    *,
    actor_identity: str = "",
    target_identity: str = "",
    artifact_identity: str = "",
    process_identity: str = "",
    host_identity: str = "",
    connection_identity: str = "",
    source_location: ObservationSourceLocation,
    ordinal: int | None = None,
    timestamp: float | None = None,
) -> str:
    """Derive one root from physical identity, independent of producer labels."""
    payload = json.dumps(
        _physical_identity_record(
            actor_identity=actor_identity,
            target_identity=target_identity,
            artifact_identity=artifact_identity,
            process_identity=process_identity,
            host_identity=host_identity,
            connection_identity=connection_identity,
            source_location=source_location,
            ordinal=ordinal,
            timestamp=timestamp,
        ),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8", "strict")
    return "obs_" + sha256(payload).hexdigest()[:40]


def deterministic_observation_id(
    *,
    producer_id: str,
    stage_id: str,
    modality: str,
    platform: str = "",
    actor_identity: str = "",
    target_identity: str = "",
    artifact_identity: str = "",
    process_identity: str = "",
    host_identity: str = "",
    connection_identity: str = "",
    source_location: ObservationSourceLocation,
    ordinal: int | None = None,
    timestamp: float | None = None,
) -> str:
    """Derive a physical identity without including a tag or confidence."""
    payload = json.dumps(
        _identity_record(
            producer_id=producer_id,
            stage_id=stage_id,
            modality=modality,
            platform=platform,
            actor_identity=actor_identity,
            target_identity=target_identity,
            artifact_identity=artifact_identity,
            process_identity=process_identity,
            host_identity=host_identity,
            connection_identity=connection_identity,
            source_location=source_location,
            ordinal=ordinal,
            timestamp=timestamp,
        ),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8", "strict")
    return "obs_" + sha256(payload).hexdigest()[:40]


def _unavailable_source_location() -> ObservationSourceLocation:
    return ObservationSourceLocation("unavailable")


@dataclass(frozen=True, slots=True)
class DetectionObservation:
    observation_id: str
    root_observation_id: str
    tag: str
    producer_id: str
    stage_id: str
    modality: str
    platform: str = ""
    actor_identity: str = ""
    target_identity: str = ""
    artifact_identity: str = ""
    process_identity: str = ""
    host_identity: str = ""
    connection_identity: str = ""
    source_location: ObservationSourceLocation = field(
        default_factory=_unavailable_source_location
    )
    ordinal: int | None = None
    timestamp: float | None = None
    timing_provenance: str = "unavailable"
    integrity_status: str = "unavailable"
    directness: str = "unavailable"
    confidence: float = 0.0
    evidence: Mapping[str, object] = field(default_factory=dict)
    unavailable_reason: str = ""

    def __post_init__(self) -> None:
        if type(self) is not DetectionObservation:
            raise TypeError("detection_observation_owner_invalid")
        tag = _observation_text(self.tag, "detection_observation_tag_invalid", maximum=256).strip().lower()
        producer = _observation_text(self.producer_id, "detection_observation_producer_invalid", maximum=256)
        stage = _observation_text(self.stage_id, "detection_observation_stage_invalid", maximum=256)
        modality = _observation_text(self.modality, "detection_observation_modality_invalid", maximum=64)
        if modality not in DETECTION_OBSERVATION_MODALITIES:
            raise ValueError("detection_observation_modality_invalid")
        platform = _optional_observation_text(self.platform, "detection_observation_platform_invalid", maximum=128)
        actor = _optional_observation_text(self.actor_identity, "detection_observation_actor_invalid")
        target = _optional_observation_text(self.target_identity, "detection_observation_target_invalid")
        artifact = _optional_observation_text(self.artifact_identity, "detection_observation_artifact_invalid")
        process = _optional_observation_text(self.process_identity, "detection_observation_process_invalid")
        host = _optional_observation_text(self.host_identity, "detection_observation_host_invalid")
        connection = _optional_observation_text(self.connection_identity, "detection_observation_connection_invalid")
        if type(self.source_location) is not ObservationSourceLocation:
            raise TypeError("detection_observation_location_invalid")
        ordinal = _optional_int(self.ordinal, "detection_observation_ordinal_invalid")
        timestamp = _optional_float(self.timestamp, "detection_observation_timestamp_invalid")
        timing = _observation_text(
            self.timing_provenance,
            "detection_observation_timing_provenance_invalid",
            maximum=128,
        )
        integrity = _observation_text(
            self.integrity_status,
            "detection_observation_integrity_invalid",
            maximum=64,
        )
        if integrity not in DETECTION_OBSERVATION_INTEGRITY_STATES:
            raise ValueError("detection_observation_integrity_invalid")
        directness = _observation_text(
            self.directness,
            "detection_observation_directness_invalid",
            maximum=64,
        )
        if directness not in DETECTION_OBSERVATION_DIRECTNESS:
            raise ValueError("detection_observation_directness_invalid")
        confidence = _confidence(self.confidence)
        unavailable = _optional_observation_text(
            self.unavailable_reason,
            "detection_observation_unavailable_reason_invalid",
            maximum=512,
        )
        has_physical_identity = bool(
            artifact
            or actor
            or target
            or process
            or host
            or connection
            or self.source_location.identifies_physical_source
        )
        if not has_physical_identity:
            unavailable = unavailable or "detection_observation_physical_identity_unavailable"
            integrity = "unavailable"
            directness = "unavailable"
            confidence = 0.0
            modality = "unavailable"
        computed = deterministic_observation_id(
            producer_id=producer,
            stage_id=stage,
            modality=modality,
            platform=platform,
            actor_identity=actor,
            target_identity=target,
            artifact_identity=artifact,
            process_identity=process,
            host_identity=host,
            connection_identity=connection,
            source_location=self.source_location,
            ordinal=ordinal,
            timestamp=timestamp,
        )
        observation_id = _optional_observation_text(
            self.observation_id,
            "detection_observation_id_invalid",
            maximum=128,
        ) or computed
        if not observation_id.startswith("obs_") or observation_id != computed:
            raise ValueError("detection_observation_id_invalid")
        computed_root = deterministic_physical_root_id(
            actor_identity=actor,
            target_identity=target,
            artifact_identity=artifact,
            process_identity=process,
            host_identity=host,
            connection_identity=connection,
            source_location=self.source_location,
            ordinal=ordinal,
            timestamp=timestamp,
        )
        root_id = _optional_observation_text(
            self.root_observation_id,
            "detection_observation_root_id_invalid",
            maximum=128,
        ) or computed_root
        if not root_id.startswith("obs_"):
            raise ValueError("detection_observation_root_id_invalid")
        evidence = _freeze_evidence(self.evidence)
        if type(evidence) is not MappingProxyType:
            raise TypeError("detection_observation_evidence_mapping_invalid")

        object.__setattr__(self, "observation_id", observation_id)
        object.__setattr__(self, "root_observation_id", root_id)
        object.__setattr__(self, "tag", tag)
        object.__setattr__(self, "producer_id", producer)
        object.__setattr__(self, "stage_id", stage)
        object.__setattr__(self, "modality", modality)
        object.__setattr__(self, "platform", platform)
        object.__setattr__(self, "actor_identity", actor)
        object.__setattr__(self, "target_identity", target)
        object.__setattr__(self, "artifact_identity", artifact)
        object.__setattr__(self, "process_identity", process)
        object.__setattr__(self, "host_identity", host)
        object.__setattr__(self, "connection_identity", connection)
        object.__setattr__(self, "ordinal", ordinal)
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "timing_provenance", timing)
        object.__setattr__(self, "integrity_status", integrity)
        object.__setattr__(self, "directness", directness)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "unavailable_reason", unavailable)

    @classmethod
    def create(
        cls,
        *,
        tag: str,
        producer_id: str,
        stage_id: str,
        modality: str,
        platform: str = "",
        actor_identity: str = "",
        target_identity: str = "",
        artifact_identity: str = "",
        process_identity: str = "",
        host_identity: str = "",
        connection_identity: str = "",
        source_location: ObservationSourceLocation,
        ordinal: int | None = None,
        timestamp: float | None = None,
        timing_provenance: str = "unavailable",
        integrity_status: str = "unverified",
        directness: str = "direct",
        confidence: float = 1.0,
        evidence: Mapping[str, object] | None = None,
        root_observation_id: str = "",
        unavailable_reason: str = "",
    ) -> "DetectionObservation":
        return cls(
            observation_id="",
            root_observation_id=root_observation_id,
            tag=tag,
            producer_id=producer_id,
            stage_id=stage_id,
            modality=modality,
            platform=platform,
            actor_identity=actor_identity,
            target_identity=target_identity,
            artifact_identity=artifact_identity,
            process_identity=process_identity,
            host_identity=host_identity,
            connection_identity=connection_identity,
            source_location=source_location,
            ordinal=ordinal,
            timestamp=timestamp,
            timing_provenance=timing_provenance,
            integrity_status=integrity_status,
            directness=directness,
            confidence=confidence,
            evidence={} if evidence is None else evidence,
            unavailable_reason=unavailable_reason,
        )

    @classmethod
    def from_value(cls, value: object) -> "DetectionObservation":
        """Hydrate only an exact-current serialized observation or accept this exact type.

        Raw detector/tag inputs are constructed by their owning scanner/projector; this
        method is an authority-bearing schema boundary and never a compatibility adapter.
        """
        if type(value) is cls:
            return value
        if type(value) is not dict:
            raise TypeError("detection_observation_record_invalid")
        expected = {
            "schema_version", "observation_id", "root_observation_id", "tag",
            "producer_id", "stage_id", "modality", "platform", "actor_identity",
            "target_identity", "artifact_identity", "process_identity",
            "host_identity", "connection_identity", "source_location", "ordinal",
            "timestamp", "timing_provenance", "integrity_status", "directness",
            "confidence", "evidence", "unavailable_reason",
        }
        if set(value) != expected:
            raise ValueError("detection_observation_fields_invalid")
        schema = dict.get(value, "schema_version")
        if type(schema) is not str:
            raise TypeError("detection_observation_schema_version_invalid")
        if schema != DETECTION_OBSERVATION_SCHEMA_VERSION:
            raise ValueError("detection_observation_schema_version_unsupported")
        location_value = dict.get(value, "source_location")
        location = (
            location_value
            if type(location_value) is ObservationSourceLocation
            else ObservationSourceLocation.from_record(location_value)
        )
        return cls(
            observation_id=dict.get(value, "observation_id"),
            root_observation_id=dict.get(value, "root_observation_id"),
            tag=dict.get(value, "tag"),
            producer_id=dict.get(value, "producer_id"),
            stage_id=dict.get(value, "stage_id"),
            modality=dict.get(value, "modality"),
            platform=dict.get(value, "platform"),
            actor_identity=dict.get(value, "actor_identity"),
            target_identity=dict.get(value, "target_identity"),
            artifact_identity=dict.get(value, "artifact_identity"),
            process_identity=dict.get(value, "process_identity"),
            host_identity=dict.get(value, "host_identity"),
            connection_identity=dict.get(value, "connection_identity"),
            source_location=location,
            ordinal=dict.get(value, "ordinal"),
            timestamp=dict.get(value, "timestamp"),
            timing_provenance=dict.get(value, "timing_provenance"),
            integrity_status=dict.get(value, "integrity_status"),
            directness=dict.get(value, "directness"),
            confidence=dict.get(value, "confidence"),
            evidence=dict.get(value, "evidence"),
            unavailable_reason=dict.get(value, "unavailable_reason"),
        )

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": DETECTION_OBSERVATION_SCHEMA_VERSION,
            "observation_id": self.observation_id,
            "root_observation_id": self.root_observation_id,
            "tag": self.tag,
            "producer_id": self.producer_id,
            "stage_id": self.stage_id,
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
            "confidence": self.confidence,
            "evidence": _materialize_evidence(self.evidence),
            "unavailable_reason": self.unavailable_reason,
        }


def artifact_observations_for_tags(
    tags: object,
    *,
    producer_id: str,
    stage_id: str,
    artifact_identity: str,
    source_location: ObservationSourceLocation,
    modality: str,
    platform: str = "",
    integrity_status: str = "unverified",
    directness: str = "direct",
) -> tuple[DetectionObservation, ...]:
    """Create conservative artifact-level observations from exact tag sequences.

    All projected tags deliberately share one physical root.  Callers with more
    precise locations must construct observations directly instead of claiming
    independence that their legacy scanner output cannot prove.
    """
    if type(tags) not in (tuple, list):
        raise TypeError("detection_observation_tag_sequence_invalid")
    if len(tags) > _MAX_OBSERVATIONS:
        raise ValueError("detection_observation_tag_sequence_exceeded")
    values: list[str] = []
    for tag in tags:
        values.append(_observation_text(tag, "detection_observation_tag_invalid", maximum=256).strip().lower())
    base_id = deterministic_physical_root_id(
        artifact_identity=artifact_identity,
        source_location=source_location,
    )
    return tuple(
        DetectionObservation.create(
            tag=tag,
            producer_id=producer_id,
            stage_id=stage_id,
            modality=modality,
            platform=platform,
            artifact_identity=artifact_identity,
            source_location=source_location,
            timing_provenance="not_observed",
            integrity_status=integrity_status,
            directness=directness,
            confidence=1.0,
            root_observation_id=base_id,
        )
        for tag in values
    )


def artifact_observations_for_path_tags(
    tags: object,
    *,
    producer_id: str,
    stage_id: str,
    path: object = None,
    strings_blob: object = "",
    modality: str = "static_structure",
    platform: str = "",
    integrity_status: str = "unverified",
    directness: str = "direct",
) -> tuple[DetectionObservation, ...]:
    """Create explicit artifact observations at a scanner-owned boundary.

    Generic finalization must never infer physical identity from flat strings.
    Scanner owners that still project exact string tags call this function
    deliberately, binding those projections to one physical artifact root until
    they can publish a more precise offset/event identity.
    """
    path_text = str.__str__(path).strip() if type(path) is str else ""
    blob_text = str.__str__(strings_blob) if type(strings_blob) is str else ""
    if blob_text:
        digest = sha256(blob_text.encode("utf-8", "surrogatepass")).hexdigest()
        artifact_identity = "content_sha256:" + digest
        source_location = ObservationSourceLocation(
            "file_content", locator=path_text or artifact_identity,
        )
    elif path_text:
        artifact_identity = "path:" + path_text
        source_location = ObservationSourceLocation("file_path", locator=path_text)
    else:
        artifact_identity = ""
        source_location = ObservationSourceLocation("unavailable")
    return artifact_observations_for_tags(
        tags,
        producer_id=producer_id,
        stage_id=stage_id,
        artifact_identity=artifact_identity,
        source_location=source_location,
        modality=modality if artifact_identity else "unavailable",
        platform=platform,
        integrity_status=integrity_status if artifact_identity else "unavailable",
        directness=directness if artifact_identity else "unavailable",
    )


def detection_observations(value: object) -> tuple[DetectionObservation, ...]:
    if value is None:
        return ()
    if type(value) is DetectionObservation:
        return (value,)
    if type(value) not in (tuple, list):
        return ()
    out: list[DetectionObservation] = []
    seen: set[tuple[str, str]] = set()
    for item in value[:_MAX_OBSERVATIONS]:
        if type(item) is not DetectionObservation:
            continue
        key = (item.observation_id, item.tag)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return tuple(out)


__all__ = (
    "DETECTION_OBSERVATION_DIRECTNESS",
    "DETECTION_OBSERVATION_INTEGRITY_STATES",
    "DETECTION_OBSERVATION_MODALITIES",
    "DETECTION_OBSERVATION_SCHEMA_VERSION",
    "DETECTION_OBSERVATION_UNAVAILABLE_TAG",
    "DetectionObservation",
    "ObservationSourceLocation",
    "artifact_observations_for_path_tags",
    "artifact_observations_for_tags",
    "detection_observations",
    "deterministic_observation_id",
    "deterministic_physical_root_id",
)
