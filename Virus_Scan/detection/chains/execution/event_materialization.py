"""Hostile-safe materialization of canonical chain evidence events."""

from __future__ import annotations

import hashlib
from math import isfinite

from Virus_Scan.contracts.chain_evidence import ChainEvent
from Virus_Scan.contracts.detection_observation import DetectionObservation, ObservationSourceLocation
from Virus_Scan.contracts.tag_evidence import TagEvidenceRecord
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.registries.chain_registry import CHAIN_CONCLUSION_TAGS


_MAX_CHAIN_EVENTS = 256
_CHAIN_TAG_KINDS = frozenset({"observed", "normalized", "derived", "suppression", "failure"})


def _static_control_flow_record(record: object) -> bool:
    return (
        type(record) is TagEvidenceRecord
        and record.modality == "static_control_flow"
        and record.timing_provenance == "static_control_flow"
        and type(record.ordinal) is int
        and type(record.ordinal) is not bool
        and record.ordinal >= 0
    )


def _ordered_tag_records(records: tuple[TagEvidenceRecord, ...]) -> tuple[TagEvidenceRecord, ...]:
    """Restore parser-owned static order without disturbing other evidence slots."""
    values = list(records)
    positions = tuple(
        index for index, record in enumerate(values)
        if _static_control_flow_record(record)
    )
    ordered = tuple(sorted(
        (values[index] for index in positions),
        key=lambda record: (
            record.ordinal,
            record.source_location.locator,
            record.source_location.event_id,
            record.root_observation_id,
            record.canonical_tag_id,
            record.evidence_id,
        ),
    ))
    for index, record in zip(positions, ordered, strict=True):
        values[index] = record
    return tuple(values)


def _sequence(value: object) -> tuple[object, ...] | None:
    if value is None:
        return ()
    if type(value) in (str, bytes, bytearray, int, float, bool):
        return (value,)
    if type(value) in (tuple, list):
        return tuple(value[:_MAX_CHAIN_EVENTS])
    return None


def _text(value: object) -> str:
    if type(value) is str:
        return str.__str__(value).strip().lower()
    if type(value) is bytes:
        try:
            return bytes(value).decode("utf-8", "replace").strip().lower()
        except (UnicodeError, ValueError, TypeError):
            return ""
    if type(value) is bytearray:
        try:
            return bytes(value).decode("utf-8", "replace").strip().lower()
        except (UnicodeError, ValueError, TypeError):
            return ""
    if type(value) is int and type(value) is not bool:
        return int.__str__(value)
    if type(value) is float and isfinite(value):
        return float.__str__(value)
    return ""


def _mapping(value: object) -> dict[str, object] | None:
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    return {key: item for key, item in items if type(key) is str}


def _event_id(source: str, ordinal: int, term: str) -> str:
    payload = f"{source}\x1f{ordinal}\x1f{term}".encode("utf-8", "strict")
    return "chain_ev_" + hashlib.sha256(payload).hexdigest()[:32]


def _observation_event(
    observation: DetectionObservation, *, source: str, ordinal: int,
) -> ChainEvent:
    """Project one exact canonical observation without trusting caller mappings."""
    if type(observation) is not DetectionObservation:
        raise TypeError("chain_detection_observation_required")
    physical_source = "timeline_observation" if source == "timeline" else "api_observation"
    return ChainEvent(
        evidence_id=observation.observation_id,
        root_evidence_id=observation.root_observation_id,
        term=observation.tag,
        source=physical_source,
        ordinal=ordinal,
        timestamp=observation.timestamp,
        correlation_group="",
        evidence_kind="observed",
        polarity="positive",
        unavailable_reason=observation.unavailable_reason,
        observation_id=observation.observation_id,
        modality=observation.modality,
        platform=observation.platform,
        actor_identity=observation.actor_identity,
        target_identity=observation.target_identity,
        artifact_identity=observation.artifact_identity,
        process_identity=observation.process_identity,
        host_identity=observation.host_identity,
        connection_identity=observation.connection_identity,
        source_location=observation.source_location,
        timing_provenance=observation.timing_provenance,
        integrity_status=observation.integrity_status,
        directness=observation.directness,
    )


def _mapping_event(
    value: object, *, source: str, ordinal: int,
) -> tuple[ChainEvent | None, str]:
    data = _mapping(value)
    if data is None:
        return None, ""
    term = ""
    for key in ("term", "event", "name", "tag", "token", "api_call", "behavior"):
        term = _text(data.get(key))
        if term:
            break
    if not term:
        return None, ""
    evidence_id = _text(data.get("evidence_id")) or _event_id(source, ordinal, term)
    root_id = _text(data.get("root_evidence_id")) or _text(data.get("root_observation_id")) or evidence_id
    timestamp_keys = ("timestamp", "event_time", "time")
    timestamp_present = any(key in data for key in timestamp_keys)
    timestamp_value = data.get("timestamp", data.get("event_time", data.get("time")))
    timestamp_valid = (
        type(timestamp_value) in (int, float)
        and type(timestamp_value) is not bool
        and isfinite(float(timestamp_value))
    )
    timestamp = float(timestamp_value) if timestamp_valid else None
    timestamp_failure = (
        "chain_event_timestamp_invalid" if timestamp_present and not timestamp_valid else ""
    )
    return ChainEvent(
        evidence_id=evidence_id,
        root_evidence_id=root_id,
        term=term,
        source=source,
        ordinal=ordinal,
        timestamp=timestamp,
        correlation_group=_text(data.get("correlation_group")),
        evidence_kind=_text(data.get("evidence_kind")) or "observed",
        polarity=_text(data.get("polarity")) or "positive",
        unavailable_reason=_text(data.get("unavailable_reason")),
        observation_id=_text(data.get("observation_id")),
        modality=_text(data.get("modality")) or "unavailable",
        platform=_text(data.get("platform")),
        actor_identity=_text(data.get("actor_identity")),
        target_identity=_text(data.get("target_identity")),
        artifact_identity=_text(data.get("artifact_identity")),
        process_identity=_text(data.get("process_identity")),
        host_identity=_text(data.get("host_identity")),
        connection_identity=_text(data.get("connection_identity")),
        source_location=(
            ObservationSourceLocation.from_record(data.get("source_location"))
            if type(data.get("source_location")) is dict
            else ObservationSourceLocation("unavailable")
        ),
        timing_provenance=_text(data.get("timing_provenance")) or "unavailable",
        integrity_status=_text(data.get("integrity_status")) or "unavailable",
        directness=_text(data.get("directness")) or "unavailable",
    ), timestamp_failure


def sequence_chain_events(
    values: object,
    *,
    source: str,
) -> tuple[tuple[ChainEvent, ...], tuple[dict[str, object], ...]]:
    """Materialize one exact ordered evidence source once."""
    if source not in {"timeline", "api_calls"}:
        raise ValueError("chain_event_source_invalid")
    raw = _sequence(values)
    failures: list[dict[str, object]] = []
    if raw is None:
        reason = (
            "ordered_event_sequence_rejected"
            if source == "timeline"
            else "api_call_sequence_rejected"
        )
        failures.append({"reason": reason, "source": source})
        raw = ()
    events: list[ChainEvent] = []
    for ordinal, value in enumerate(raw[:_MAX_CHAIN_EVENTS]):
        if type(value) is DetectionObservation:
            event = _observation_event(value, source=source, ordinal=ordinal)
            event_failure = ""
        else:
            event, event_failure = _mapping_event(value, source=source, ordinal=ordinal)
        if event_failure:
            failures.append({
                "reason": event_failure,
                "source": source,
                "ordinal": ordinal,
            })
        if event is None:
            term = _text(value)
            if not term:
                if value is not None:
                    failures.append({
                        "reason": "chain_event_rejected",
                        "source": source,
                        "ordinal": ordinal,
                    })
                continue
            evidence_id = _event_id(source, ordinal, term)
            event = ChainEvent(
                evidence_id=evidence_id,
                root_evidence_id=evidence_id,
                term=term,
                source=source,
                ordinal=ordinal,
            )
        events.append(event)
    return tuple(events), tuple(failures[:64])


def tag_chain_events(tags: object) -> tuple[tuple[ChainEvent, ...], tuple[dict[str, object], ...]]:
    """Project positive non-composite tag evidence into root-preserving chain events."""
    bundle = tags if type(tags) is TagEvidence else normalize_tag_evidence(
        tags,
        source_detector="canonical_chain_evaluator",
        source_stage="behavior_evidence_input",
    )
    events: list[ChainEvent] = []
    failures: list[dict[str, object]] = []
    ordered_records = _ordered_tag_records(bundle.records[:_MAX_CHAIN_EVENTS])
    for materialized_ordinal, record in enumerate(ordered_records):
        ordinal = record.ordinal if _static_control_flow_record(record) else materialized_ordinal
        if record.evidence_kind not in _CHAIN_TAG_KINDS:
            continue
        if record.source_stage.startswith("chain") or record.source_detector.startswith("chain"):
            continue
        if record.canonical_tag_id in CHAIN_CONCLUSION_TAGS:
            continue
        polarity = record.polarity
        unavailable_reason = record.unavailable_reason
        if record.evidence_kind == "failure":
            polarity = "neutral"
            unavailable_reason = unavailable_reason or "tag_evidence_failure"
            failures.append({
                "reason": unavailable_reason,
                "source": "tag_evidence",
                "ordinal": ordinal,
                "evidence_id": record.evidence_id,
                "evidence_kind": record.evidence_kind,
            })
        try:
            events.append(ChainEvent(
                evidence_id=record.evidence_id,
                root_evidence_id=record.root_observation_id,
                term=record.canonical_tag_id,
                source=("tag_evidence" if record.has_physical_identity else "tag_context"),
                ordinal=ordinal,
                correlation_group=record.correlation_group,
                evidence_kind=record.evidence_kind,
                polarity=polarity,
                unavailable_reason=unavailable_reason,
                observation_id=record.observation_id,
                modality=record.modality,
                platform=record.platform,
                actor_identity=record.actor_identity,
                target_identity=record.target_identity,
                artifact_identity=record.artifact_identity,
                process_identity=record.process_identity,
                host_identity=record.host_identity,
                connection_identity=record.connection_identity,
                source_location=record.source_location,
                timestamp=record.timestamp,
                timing_provenance=record.timing_provenance,
                integrity_status=record.integrity_status,
                directness=record.directness,
            ))
        except ValueError as error:
            failures.append({
                "reason": str(error),
                "source": "tag_evidence",
                "ordinal": ordinal,
                "evidence_id": record.evidence_id,
                "evidence_kind": record.evidence_kind,
            })
    reason = bundle.reasons.get("unavailable_reason")
    if type(reason) is str and reason:
        failures.append({"reason": reason, "source": "tag_evidence"})
    return tuple(events), tuple(failures[:64])


def merge_chain_events(
    tag_events: tuple[ChainEvent, ...],
    api_events: tuple[ChainEvent, ...],
) -> tuple[ChainEvent, ...]:
    """Merge already-materialized canonical evidence without re-normalization."""
    if type(tag_events) is not tuple or type(api_events) is not tuple:
        raise TypeError("canonical_chain_event_tuples_required")
    offset = len(tag_events)
    adjusted = tuple(ChainEvent(
        evidence_id=event.evidence_id,
        root_evidence_id=event.root_evidence_id,
        term=event.term,
        source=event.source,
        ordinal=offset + event.ordinal,
        timestamp=event.timestamp,
        correlation_group=event.correlation_group,
        evidence_kind=event.evidence_kind,
        polarity=event.polarity,
        unavailable_reason=event.unavailable_reason,
        observation_id=event.observation_id,
        modality=event.modality,
        platform=event.platform,
        actor_identity=event.actor_identity,
        target_identity=event.target_identity,
        artifact_identity=event.artifact_identity,
        process_identity=event.process_identity,
        host_identity=event.host_identity,
        connection_identity=event.connection_identity,
        source_location=event.source_location,
        timing_provenance=event.timing_provenance,
        integrity_status=event.integrity_status,
        directness=event.directness,
    ) for event in api_events if type(event) is ChainEvent)
    return tuple((*tag_events, *adjusted))[:_MAX_CHAIN_EVENTS]


__all__ = ("merge_chain_events", "sequence_chain_events", "tag_chain_events")
