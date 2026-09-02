"""Canonical immutable physical-evidence fixtures for semantic contract tests."""

from dataclasses import replace

from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
    artifact_observations_for_tags,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence


def physical_tag_evidence(
    tags: tuple[str, ...],
    *,
    one_root: bool = False,
    correlation_group: str = "",
    source_detector: str = "canonical_physical_fixture",
    source_stage: str = "physical_observation",
) -> TagEvidence:
    """Build scoreable evidence with explicit artifact/event identity."""
    if one_root:
        observations = artifact_observations_for_tags(
            list(tags),
            producer_id=source_detector,
            stage_id=source_stage,
            artifact_identity="sha256:canonical-fixture",
            source_location=ObservationSourceLocation(
                "fixture_artifact",
                locator="canonical-fixture.bin",
                event_id=source_stage + ":shared",
            ),
            modality="static_structure",
            integrity_status="verified",
            directness="direct",
        )
    else:
        observations = tuple(
            DetectionObservation.create(
                tag=tag,
                producer_id=source_detector,
                stage_id=source_stage,
                modality="static_structure",
                artifact_identity="sha256:canonical-fixture",
                source_location=ObservationSourceLocation(
                    "fixture_event",
                    locator="canonical-fixture.bin",
                    event_id=source_stage + ":event-" + int.__str__(index),
                ),
                ordinal=index,
                timing_provenance="fixture_order",
                integrity_status="verified",
                directness="direct",
                confidence=1.0,
            )
            for index, tag in enumerate(tags)
        )
    bundle = normalize_tag_evidence(
        observations,
        source_detector=source_detector,
        source_stage=source_stage,
    )
    if not correlation_group:
        return bundle
    return TagEvidence.from_records(tuple(
        replace(record, correlation_group=correlation_group)
        for record in bundle.records
    ))


def causal_tag_evidence(
    tags: tuple[str, ...],
    *,
    correlation_group: str,
    source_detector: str = "canonical_chain_fixture",
    source_stage: str = "causal_observation",
) -> TagEvidence:
    """Build distinct physical roots linked by one explicit causal group."""
    return physical_tag_evidence(
        tags,
        correlation_group=correlation_group,
        source_detector=source_detector,
        source_stage=source_stage,
    )


def physical_runtime_chain_event(
    term: str,
    timestamp: float,
    index: int,
    *,
    source_detector: str = "canonical_runtime_fixture",
    platform: str = "windows",
    target_identity: str = "process:4242",
    process_identity: str = "process:4242",
) -> DetectionObservation:
    """Build one exact canonical runtime observation for Chain evaluation."""
    observation = DetectionObservation.create(
        tag=term.lower(),
        producer_id=source_detector,
        stage_id="runtime_event",
        modality="host_telemetry",
        platform=platform,
        target_identity=target_identity,
        process_identity=process_identity,
        source_location=ObservationSourceLocation(
            "host_event",
            locator=source_detector,
            event_id=f"event:{index}:{term.lower()}",
        ),
        timestamp=timestamp,
        timing_provenance="runtime_timestamp",
        integrity_status="verified",
        directness="direct",
        confidence=1.0,
    )
    return observation


__all__ = ("causal_tag_evidence", "physical_runtime_chain_event", "physical_tag_evidence")
