"""Immutable detection-profile contracts.

Phase 7 keeps engine-specific detection profile state in detection/profile
owners.  These contracts are frozen snapshots only; scan stages receive profile
context explicitly rather than mutating global engine/profile state.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field

from Virus_Scan.detection.models.stage_value_utils import (
    detection_unavailable_value,
    freeze_mapping_or_empty,
    frozen_tuple_or_empty,
)
from Virus_Scan.detection.registries.immutability import freeze_registry_value
from Virus_Scan.contracts.no_hook_materialization import no_hook_text


ProfileValue = object
ProfileEvidence = Mapping[str, ProfileValue]


def _profile_evidence(reason: str, value: ProfileValue) -> ProfileEvidence:
    return detection_unavailable_value(reason, value)


def _record_failure(records: list[ProfileEvidence], evidence: ProfileEvidence | None) -> None:
    if evidence is not None:
        records.append(evidence)


def _profile_text(value: ProfileValue, replacement: str, reason: str, *, lower: bool = False) -> tuple[str, ProfileEvidence | None]:
    if value is None:
        return replacement, None
    text, text_reason = no_hook_text(
        value,
        missing_reason=reason,
        unsupported_reason=reason,
    )
    if text_reason:
        return replacement, _profile_evidence(reason, value)
    text = text.strip()
    if text == "":
        return replacement, None
    return (text.lower() if lower else text), None


def _selected_profile(value: ProfileValue) -> tuple[ProfileValue, tuple[ProfileEvidence, ...]]:
    if type(value) is not DetectionProfileSnapshot:
        evidence = _profile_evidence("profile_context_selected_profile_unavailable", value)
        profile = DetectionProfileSnapshot(
            name="other",
            aliases=("other",),
            tag_markers=frozenset(),
            file_extensions=frozenset(),
            baseline_suppression_profile="other",
            selected_engine_context_key="other",
            failure_evidence=(evidence,),
        )
        return profile, (evidence,)
    return value, frozen_tuple_or_empty(value.failure_evidence)


def _profile_text_tuple(value: ProfileValue, reason: str, *, lower: bool = False) -> tuple[tuple[str, ...], tuple[ProfileEvidence, ...]]:
    items = frozen_tuple_or_empty(value)
    failures: list[ProfileEvidence] = []
    normalized: list[str] = []
    for item in items:
        if isinstance(item, Mapping) and item.get("unavailable_reason"):
            failures.append(_profile_evidence(reason, item))
            continue
        text, evidence = _profile_text(item, "", reason, lower=lower)
        _record_failure(failures, evidence)
        if text:
            normalized.append(text)
    return tuple(normalized), tuple(failures)


def _profile_mapping(value: ProfileValue, reason: str) -> tuple[ProfileValue, tuple[ProfileEvidence, ...]]:
    frozen = freeze_mapping_or_empty(value)
    if isinstance(frozen, Mapping) and frozen.get("unavailable_reason"):
        return frozen, (_profile_evidence(reason, value),)
    return frozen, ()


@dataclass(frozen=True, slots=True)
class DetectionProfileSnapshot:
    """Immutable profile definition for one detection engine family."""

    name: str
    aliases: tuple[str, ...]
    tag_markers: frozenset[str]
    file_extensions: frozenset[str]
    baseline_suppression_profile: str
    selected_engine_context_key: str
    failure_evidence: tuple[ProfileEvidence, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Deep-freeze profile snapshot constructor inputs."""
        failures: list[ProfileEvidence] = []
        name, evidence = _profile_text(self.name, "other", "profile_snapshot_name_unavailable", lower=True)
        _record_failure(failures, evidence)
        aliases, alias_failures = _profile_text_tuple(self.aliases, "profile_snapshot_aliases_unavailable", lower=True)
        markers, marker_failures = _profile_text_tuple(self.tag_markers, "profile_snapshot_tag_markers_unavailable")
        extensions, extension_failures = _profile_text_tuple(self.file_extensions, "profile_snapshot_file_extensions_unavailable", lower=True)
        baseline, evidence = _profile_text(
            self.baseline_suppression_profile,
            "other",
            "profile_snapshot_baseline_suppression_profile_unavailable",
        )
        _record_failure(failures, evidence)
        context_key, evidence = _profile_text(
            self.selected_engine_context_key,
            "unknown",
            "profile_snapshot_selected_engine_context_key_unavailable",
        )
        _record_failure(failures, evidence)
        failures.extend(alias_failures)
        failures.extend(marker_failures)
        failures.extend(extension_failures)
        failures.extend(frozen_tuple_or_empty(self.failure_evidence))

        object.__setattr__(self, "name", name)
        object.__setattr__(self, "aliases", aliases)
        object.__setattr__(self, "tag_markers", frozenset(markers))
        object.__setattr__(self, "file_extensions", frozenset(extensions))
        object.__setattr__(self, "baseline_suppression_profile", baseline)
        object.__setattr__(self, "selected_engine_context_key", context_key)
        object.__setattr__(self, "failure_evidence", tuple(freeze_registry_value(failure) for failure in failures))

    def matches_name(self, value: object) -> bool:
        normalized, _ = _profile_text(value, "other", "profile_match_name_unavailable", lower=True)
        return normalized == self.name or normalized in self.aliases

    def to_record(self) -> ProfileEvidence:
        return freeze_registry_value(
            {
                "name": self.name,
                "aliases": self.aliases,
                "tag_markers": tuple(sorted(self.tag_markers)),
                "file_extensions": tuple(sorted(self.file_extensions)),
                "baseline_suppression_profile": self.baseline_suppression_profile,
                "selected_engine_context_key": self.selected_engine_context_key,
                "failure_evidence": self.failure_evidence,
            }
        )


@dataclass(frozen=True, slots=True)
class DetectionProfileContext:
    """Immutable active profile context selected for one detection analysis."""

    active_profile: str
    selected_profile: DetectionProfileSnapshot
    engine_context: ProfileEvidence
    engine_confidence: ProfileEvidence
    selection_reasons: tuple[str, ...]
    failure_evidence: tuple[ProfileEvidence, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Deep-freeze selected profile context constructor inputs."""
        failures: list[ProfileEvidence] = []
        active_profile, evidence = _profile_text(self.active_profile, "other", "profile_context_active_profile_unavailable")
        _record_failure(failures, evidence)
        engine_context, context_failures = _profile_mapping(self.engine_context, "profile_context_engine_context_unavailable")
        engine_confidence, confidence_failures = _profile_mapping(
            self.engine_confidence,
            "profile_context_engine_confidence_unavailable",
        )
        selection_reasons, reason_failures = _profile_text_tuple(
            self.selection_reasons,
            "profile_context_selection_reasons_unavailable",
        )
        selected_profile, selected_profile_failures = _selected_profile(self.selected_profile)
        failures.extend(context_failures)
        failures.extend(confidence_failures)
        failures.extend(reason_failures)
        failures.extend(selected_profile_failures)
        failures.extend(frozen_tuple_or_empty(self.failure_evidence))

        object.__setattr__(self, "active_profile", active_profile)
        object.__setattr__(self, "selected_profile", selected_profile)
        object.__setattr__(self, "engine_context", engine_context)
        object.__setattr__(self, "engine_confidence", engine_confidence)
        object.__setattr__(self, "selection_reasons", selection_reasons)
        object.__setattr__(self, "failure_evidence", tuple(freeze_registry_value(failure) for failure in failures))

    def to_record(self) -> ProfileEvidence:
        return freeze_registry_value(
            {
                "active_profile": self.active_profile,
                "selected_profile": self.selected_profile.to_record(),
                "engine_context": self.engine_context,
                "engine_confidence": self.engine_confidence,
                "selection_reasons": self.selection_reasons,
                "profile_selection_mode": "immutable_detection_profile_context",
                "failure_evidence": self.failure_evidence,
            }
        )


__all__ = (
    "DetectionProfileContext",
    "DetectionProfileSnapshot",
)
