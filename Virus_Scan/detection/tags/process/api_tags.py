"""Canonical detection classification owner for API-call-derived observations."""
from __future__ import annotations

from Virus_Scan.contracts.api_behavior import (
    API_NAME_TEXT_UNAVAILABLE,
    api_call_values,
    canonical_api_text,
    map_api_to_group,
)
from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags
from Virus_Scan.detection.tags.process.spyware_gate import gate_spyware_collection_chains
from Virus_Scan.utils.tagging import (
    DETECTION_STAGE_DEGRADED_TAG,
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    ordered_unique_tags,
)

_API_GROUP_TAGS = (
    ("process_execution", ("process_exec",)),
    ("process_access", ("process_access",)),
    ("memory", ("memory_access", "memory_read")),
    ("threading", ("thread_execution",)),
    ("dll", ("dll_load",)),
    ("credentials", ("credential_access", "credential_access_attempt")),
    ("registry", ("registry_mod",)),
    ("filesystem", ("file_access",)),
    ("network", ("network_activity",)),
    ("services", ("lateral_movement",)),
    ("evasion", ("defense_evasion",)),
    ("collection", ("collection_capability",)),
)


def _tags_for_api_group(group: object) -> tuple[str, ...]:
    for known_group, group_tags in _API_GROUP_TAGS:
        if group == known_group:
            return group_tags
    return ()


def _indicator_tags(api_name: str) -> tuple[str, ...]:
    if api_name == "getasynckeystate":
        return ("keylogging_behavior", "input_capture")
    if api_name in {"bitblt", "printwindow"}:
        return ("screenshot_capture", "screen_capture")
    if api_name in {"getforegroundwindow", "getdc"}:
        return ("user_activity_monitoring", "spyware_behavior")
    return ()


def infer_observations_from_api(
    api_calls: object,
    *,
    artifact_identity: str = "",
    producer_id: str = "api_call_classifier",
    platform: str = "",
) -> tuple[DetectionObservation, ...]:
    """Project each exact API call into root-preserving factual observations."""
    calls = api_call_values(api_calls)
    out: list[DetectionObservation] = []
    for ordinal, api in enumerate(calls[:256]):
        api_name = canonical_api_text(api).lower()
        tags = list(_tags_for_api_group(map_api_to_group(api)))
        tags.extend(_indicator_tags(api_name))
        if api_name == API_NAME_TEXT_UNAVAILABLE:
            tags.extend((TAG_NORMALIZATION_FAILURE_EVIDENCE, DETECTION_STAGE_DEGRADED_TAG))
        if not tags:
            continue
        location = ObservationSourceLocation(
            "api_call",
            locator=artifact_identity,
            event_id="api:" + int.__str__(ordinal) + ":" + api_name,
        )
        root = ""
        for tag in tuple(dict.fromkeys(tags)):
            observation = DetectionObservation.create(
                tag=tag,
                producer_id=producer_id,
                stage_id="api_classification",
                modality="static_structure" if artifact_identity else "unavailable",
                platform=platform,
                artifact_identity=artifact_identity,
                source_location=location,
                ordinal=ordinal,
                timing_provenance="ordered_artifact_reference",
                integrity_status="unverified" if artifact_identity else "unavailable",
                directness="direct" if artifact_identity else "unavailable",
                confidence=1.0 if artifact_identity else 0.0,
                root_observation_id=root,
                unavailable_reason="" if artifact_identity else "api_artifact_identity_unavailable",
                evidence={"api_name": api_name},
            )
            root = observation.root_observation_id
            out.append(observation)
    return tuple(out)


def infer_tags_from_api(api_calls: object, tags: object = None) -> object:
    """Return a deterministic reporting projection; observations stay canonical."""
    inferred_tags = set(ordered_unique_tags(tags))
    for observation in infer_observations_from_api(api_calls):
        inferred_tags.add(observation.tag)
    ordered_tags = sorted(inferred_tags)
    return normalize_tags(gate_spyware_collection_chains(ordered_tags))


__all__ = ("infer_observations_from_api", "infer_tags_from_api")
