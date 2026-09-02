"""Immutable detection profile selection ownership.

Detection stages consume this context explicitly. Engine-specific profile
snapshots live under their bounded profile packages; generic profile code does
not import engine-specific modules.
"""

from types import MappingProxyType
from typing import Mapping

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.profiles.contracts import DetectionProfileContext, DetectionProfileSnapshot
from Virus_Scan.detection.evidence.failure_evidence import recoverable_failure_evidence
from Virus_Scan.detection.profiles.generic.profile import DETECTION_PROFILE as GENERIC_PROFILE
from Virus_Scan.detection.profiles.media.profile import DETECTION_PROFILE as MEDIA_PROFILE
from Virus_Scan.detection.profiles.renpy.profile import DETECTION_PROFILE as RENPY_PROFILE
from Virus_Scan.detection.profiles.rpgm.profile import DETECTION_PROFILE as RPGM_PROFILE
from Virus_Scan.detection.profiles.unity.profile import DETECTION_PROFILE as UNITY_PROFILE
from Virus_Scan.detection.registries.immutability import freeze_registry_value
from Virus_Scan.detection.profiles.engine_context import engine_confidence_report, select_active_profile_engine
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_sequence_items,
    no_hook_text,
    no_hook_type_name,
)


_DETECTION_PROFILE_NAMES = (
    RENPY_PROFILE.name,
    RPGM_PROFILE.name,
    UNITY_PROFILE.name,
    MEDIA_PROFILE.name,
    GENERIC_PROFILE.name,
)
_DETECTION_PROFILE_BY_NAME = MappingProxyType(
    {
        RENPY_PROFILE.name: RENPY_PROFILE,
        RPGM_PROFILE.name: RPGM_PROFILE,
        UNITY_PROFILE.name: UNITY_PROFILE,
        MEDIA_PROFILE.name: MEDIA_PROFILE,
        GENERIC_PROFILE.name: GENERIC_PROFILE,
    }
)
DETECTION_PROFILE_NAMES = _DETECTION_PROFILE_NAMES


def _mapping_snapshot(value: object, *, default: Mapping[str, object] | None = None) -> dict[object, object]:
    """Detach profile engine context without caller-owned mapping hooks."""
    default_items = () if default is None else no_hook_mapping_items(default)
    default_snapshot = (
        {}
        if default_items is None
        else {
            key: no_hook_materialize(item, reason_prefix="profile_context_default")
            for key, item in default_items
        }
    )
    if value is None:
        return default_snapshot
    items = no_hook_mapping_items(value)
    if items is None:
        return default_snapshot
    if len(items) == 0:
        return default_snapshot
    return {key: no_hook_materialize(item, reason_prefix="profile_context_engine") for key, item in items}


def _optional_reasons(value: object) -> tuple[object, ...]:
    """Return reason sequence without caller-owned truthiness or iteration."""
    return no_hook_sequence_items(value)


def _selection_reason_text(value: object) -> str:
    """Detach profile-selection reason text before immutable context materialization."""
    text, reason = no_hook_text(
        value,
        missing_reason="profile_selection_reason_missing",
        unsupported_reason="profile_selection_reason_unavailable",
    )
    if reason:
        return ""
    return text.strip()


def _confidence_error_text(error: BaseException) -> str:
    """Materialize recoverable confidence errors without caller-owned text hooks."""
    type_name = no_hook_type_name(error)
    text, reason = no_hook_text(
        error,
        missing_reason="profile_engine_confidence_error_missing",
        unsupported_reason="profile_engine_confidence_error_unavailable",
    )
    if reason:
        return type_name
    text = text.strip()
    return text if text != "" else type_name


def _iter_detection_profiles() -> tuple[DetectionProfileSnapshot, ...]:
    """Return deterministic immutable profile snapshots from the private registry."""
    return tuple(_DETECTION_PROFILE_BY_NAME[name] for name in _DETECTION_PROFILE_NAMES)


def profile_for_engine(engine: object) -> DetectionProfileSnapshot:
    """Return the immutable detection profile snapshot for an engine name."""
    for profile in _iter_detection_profiles():
        if profile.matches_name(engine):
            return profile
    return GENERIC_PROFILE


def canonical_profile_name(engine: object) -> str:
    """Normalize engine/profile names through detection-owned profile snapshots."""
    return profile_for_engine(engine).name


def _confidence_or_default(engine_context: object, path: object, tags: object, strings_blob: object, *, engine_confidence_reporter: object=engine_confidence_report) -> object:
    try:
        return engine_confidence_reporter(
            _mapping_snapshot(engine_context),
            path=path,
            tags=tags,
            strings_blob=strings_blob,
        )
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        active = select_active_profile_engine(engine_context)
        failure = recoverable_failure_evidence(
            stage_name="profile_engine_confidence",
            error=error,
            error_source="engine_confidence_report",
            affected_context=path,
        ).to_record()
        return {
            "active_profile": canonical_profile_name(active),
            "baseline_suppression_allowed": canonical_profile_name(active) == "other",
            "error": _confidence_error_text(error),
            "error_category": no_hook_type_name(error),
            "degraded": True,
            "confidence_degraded": True,
            "failure_evidence": (failure,),
            "scan_integrity": {
                "ok": False,
                "json_record_required": True,
                "replay_record_required": True,
                "failure_count": 1,
            },
        }


def build_detection_profile_context(*, engine_context: object, path: object, tags: object, strings_blob: object, engine_confidence_reporter: object=engine_confidence_report) -> DetectionProfileContext:
    """Build the immutable active profile context for one detection analysis."""
    engine_context_snapshot = freeze_registry_value(_mapping_snapshot(engine_context, default={"other": 1.0}))
    confidence = dict(_confidence_or_default(engine_context_snapshot, path, tags, strings_blob, engine_confidence_reporter=engine_confidence_reporter))
    active_candidate = confidence.get("active_profile")
    if active_candidate is None or active_candidate == "":
        active_candidate = select_active_profile_engine(engine_context_snapshot)
    active = canonical_profile_name(active_candidate)
    selected = profile_for_engine(active)
    confidence["active_profile"] = selected.name
    confidence["selected_engine_context_key"] = selected.selected_engine_context_key
    confidence["profile_selection_mode"] = "immutable_detection_profile_context"
    reasons = tuple(
        text
        for text in (_selection_reason_text(reason) for reason in _optional_reasons(confidence.get("reasons", ())))
        if text != ""
    )
    if len(reasons) == 0:
        reasons = ("selected_from_engine_context",)
    return DetectionProfileContext(
        active_profile=selected.name,
        selected_profile=selected,
        engine_context=engine_context_snapshot,
        engine_confidence=freeze_registry_value(confidence),
        selection_reasons=reasons,
    )


__all__ = (
    "DETECTION_PROFILE_NAMES",
    "build_detection_profile_context",
    "canonical_profile_name",
    "profile_for_engine",
)
