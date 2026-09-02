"""Immutable contracts for deterministic ATT&CK capability-gap reports."""
from __future__ import annotations

from Virus_Scan.contracts.numeric_boundaries import exact_bounded_nonnegative_int
from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass
from hashlib import sha256
import json

from Virus_Scan.detection.attack.validation import exact_hex, official_attack_id, ordered_text_tuple

ATTACK_GAP_ANALYSIS_VERSION = "stage2636_10011_attack_gap_analysis_v1"
ATTACK_GAP_CLASSIFICATIONS = frozenset({"exact", "partial", "unsupported"})
ATTACK_BINDING_STATES = frozenset({"current", "stale", "missing", "unbound"})
MAX_ANALYTIC_GAP_RECORDS = 100_000


@dataclass(frozen=True, slots=True)
class AttackAnalyticObservability:
    """One official Analytic binding compared with reviewed local capabilities."""

    technique_id: str
    strategy_id: str
    analytic_id: str
    requirement_digest: str
    required_data_component_ids: tuple[str, ...]
    required_platforms: tuple[str, ...]
    mutable_fields: tuple[str, ...]
    log_source_requirements: tuple[str, ...]
    classification: str
    matched_tag_ids: tuple[str, ...]
    matched_producer_ids: tuple[str, ...]
    missing_data_component_ids: tuple[str, ...]
    missing_producer_ids: tuple[str, ...]
    missing_observation_fields: tuple[str, ...]
    missing_modalities: tuple[str, ...]
    missing_platforms: tuple[str, ...]
    draft_observation_ids: tuple[str, ...]
    draft_chain_id: str
    proposal_state: str
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self) is not AttackAnalyticObservability:
            raise TypeError("attack_gap_analytic_owner_invalid")
        technique_id = exact_bounded_text(
            self.technique_id,
            "attack_gap_technique_invalid",
            maximum=16,
            allow_blank=True,
        )
        if technique_id:
            technique_id = official_attack_id(
                technique_id, "attack_gap_technique_invalid",
            )
        object.__setattr__(self, "technique_id", technique_id)
        for field_name, maximum, allow_blank in (
            ("strategy_id", 16, True),
            ("analytic_id", 16, False),
            ("draft_chain_id", 160, False),
        ):
            object.__setattr__(self, field_name, exact_bounded_text(
                object.__getattribute__(self, field_name),
                "attack_gap_identity_invalid",
                maximum=maximum,
                allow_blank=allow_blank,
            ))
        if bool(self.technique_id) != bool(self.strategy_id):
            raise ValueError("attack_gap_binding_identity_invalid")
        object.__setattr__(self, "requirement_digest", exact_hex(
            self.requirement_digest,
            "attack_gap_requirement_digest_invalid",
            length=64,
        ))
        tuple_fields = (
            ("required_data_component_ids", 256), ("required_platforms", 64),
            ("mutable_fields", 256), ("log_source_requirements", 512),
            ("matched_tag_ids", 512), ("matched_producer_ids", 256),
            ("missing_data_component_ids", 256), ("missing_producer_ids", 256),
            ("missing_observation_fields", 64), ("missing_modalities", 16),
            ("missing_platforms", 64), ("draft_observation_ids", 256),
            ("limitations", 64),
        )
        for field_name, maximum in tuple_fields:
            object.__setattr__(self, field_name, ordered_text_tuple(
                object.__getattribute__(self, field_name),
                "attack_gap_tuple_invalid",
                maximum_items=maximum,
            ))
        classification = exact_bounded_text(
            self.classification,
            "attack_gap_classification_invalid",
            maximum=32,
        )
        if classification not in ATTACK_GAP_CLASSIFICATIONS:
            raise ValueError("attack_gap_classification_invalid")
        proposal = exact_bounded_text(
            self.proposal_state,
            "attack_gap_proposal_state_invalid",
            maximum=32,
        )
        if proposal != "draft_only_not_activated":
            raise ValueError("attack_gap_proposal_state_invalid")
        if classification == "exact" and self._has_gaps():
            raise ValueError("attack_gap_exact_contract_invalid")
        if not self.technique_id and (
            classification != "unsupported"
            or "official_analytic_unbound_to_active_strategy" not in self.limitations
        ):
            raise ValueError("attack_gap_unbound_analytic_contract_invalid")
        object.__setattr__(self, "classification", classification)
        object.__setattr__(self, "proposal_state", proposal)

    def _has_gaps(self) -> bool:
        return bool(
            self.missing_data_component_ids
            or self.missing_producer_ids
            or self.missing_observation_fields
            or self.missing_modalities
            or self.missing_platforms
            or self.limitations
        )

    def to_record(self) -> dict[str, object]:
        return {
            field: object.__getattribute__(self, field)
            for field in self.__slots__
        }


@dataclass(frozen=True, slots=True)
class AttackImplementationBindingStatus:
    """Current requirement-digest status for one local implementation binding."""

    implementation_id: str
    technique_id: str
    analytic_id: str
    binding_state: str
    bound_requirement_digest: str
    current_requirement_digest: str
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self) is not AttackImplementationBindingStatus:
            raise TypeError("attack_gap_binding_owner_invalid")
        object.__setattr__(self, "implementation_id", exact_bounded_text(
            self.implementation_id,
            "attack_gap_implementation_invalid",
            maximum=128,
        ))
        object.__setattr__(self, "technique_id", official_attack_id(
            self.technique_id, "attack_gap_technique_invalid",
        ))
        object.__setattr__(self, "analytic_id", exact_bounded_text(
            self.analytic_id,
            "attack_gap_analytic_invalid",
            maximum=16,
            allow_blank=True,
        ))
        state = exact_bounded_text(
            self.binding_state, "attack_gap_binding_state_invalid", maximum=16,
        )
        if state not in ATTACK_BINDING_STATES:
            raise ValueError("attack_gap_binding_state_invalid")
        object.__setattr__(self, "binding_state", state)
        self._validate_digests()
        reasons = ordered_text_tuple(
            self.reasons,
            "attack_gap_binding_reasons_invalid",
            maximum_items=16,
        )
        if state == "current" and reasons:
            raise ValueError("attack_gap_current_binding_reason_invalid")
        if state != "current" and not reasons:
            raise ValueError("attack_gap_binding_reason_required")
        object.__setattr__(self, "reasons", reasons)

    def _validate_digests(self) -> None:
        for field_name in ("bound_requirement_digest", "current_requirement_digest"):
            value = object.__getattribute__(self, field_name)
            if value:
                value = exact_hex(
                    value, "attack_gap_binding_digest_invalid", length=64,
                )
            elif type(value) is not str:
                raise TypeError("attack_gap_binding_digest_invalid")
            object.__setattr__(self, field_name, value)

    def to_record(self) -> dict[str, object]:
        return {
            "implementation_id": self.implementation_id,
            "technique_id": self.technique_id,
            "analytic_id": self.analytic_id,
            "binding_state": self.binding_state,
            "bound_requirement_digest": self.bound_requirement_digest,
            "current_requirement_digest": self.current_requirement_digest,
            "reasons": self.reasons,
        }


def _report_record(
    values: dict[str, object],
    report_digest: str,
) -> dict[str, object]:
    return {
        "version": values["version"],
        "repository_digest": values["repository_digest"],
        "dataset_version": values["dataset_version"],
        "source_ref": values["source_ref"],
        "repository_counts": {
            "objects": values["repository_object_count"],
            "active_detection_strategies": values["active_strategy_count"],
            "active_analytics": values["active_analytic_count"],
            "active_data_components": values["active_data_component_count"],
        },
        "local_counts": {
            "capabilities": values["capability_count"],
            "active_alignments": values["active_alignment_count"],
            "admission_records": values["admission_record_count"],
            "candidate_only": values["candidate_only_count"],
            "unsupported_policies": values["unsupported_policy_count"],
        },
        "local_manifest_digests": {
            "capabilities": values["capability_manifest_digest"],
            "alignments": values["alignment_manifest_digest"],
            "implementations": values["implementation_manifest_digest"],
            "admissions": values["admission_manifest_digest"],
            "combined": values["local_manifest_digest"],
        },
        "classification_counts": {
            "exact": values["exact_count"],
            "partial": values["partial_count"],
            "unsupported": values["unsupported_count"],
        },
        "analytics": tuple(item.to_record() for item in values["analytics"]),
        "implementation_bindings": tuple(
            item.to_record() for item in values["implementation_bindings"]
        ),
        "report_digest": report_digest,
    }


def _attack_gap_report_digest(values: dict[str, object]) -> str:
    record = _report_record(values, "")
    payload = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class AttackCapabilityGapReport:
    """Bounded deterministic report with no production-policy mutation path."""

    repository_digest: str
    dataset_version: str
    source_ref: str
    repository_object_count: int
    active_strategy_count: int
    active_analytic_count: int
    active_data_component_count: int
    capability_count: int
    active_alignment_count: int
    admission_record_count: int
    candidate_only_count: int
    unsupported_policy_count: int
    capability_manifest_digest: str
    alignment_manifest_digest: str
    implementation_manifest_digest: str
    admission_manifest_digest: str
    local_manifest_digest: str
    exact_count: int
    partial_count: int
    unsupported_count: int
    analytics: tuple[AttackAnalyticObservability, ...]
    implementation_bindings: tuple[AttackImplementationBindingStatus, ...]
    report_digest: str
    version: str = ATTACK_GAP_ANALYSIS_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttackCapabilityGapReport:
            raise TypeError("attack_gap_report_owner_invalid")
        self._validate_identities()
        self._validate_records()
        self._validate_counts()
        values = self._values()
        if self.report_digest != _attack_gap_report_digest(values):
            raise ValueError("attack_gap_report_digest_invalid")

    def _validate_identities(self) -> None:
        object.__setattr__(self, "repository_digest", exact_hex(
            self.repository_digest,
            "attack_gap_repository_digest_invalid",
            length=64,
        ))
        object.__setattr__(self, "dataset_version", exact_hex(
            self.dataset_version,
            "attack_gap_dataset_version_invalid",
            length=40,
        ))
        object.__setattr__(self, "source_ref", exact_bounded_text(
            self.source_ref, "attack_gap_source_ref_invalid", maximum=256,
        ))
        for field_name in (
            "capability_manifest_digest", "alignment_manifest_digest",
            "implementation_manifest_digest", "admission_manifest_digest",
            "local_manifest_digest", "report_digest",
        ):
            object.__setattr__(self, field_name, exact_hex(
                object.__getattribute__(self, field_name),
                "attack_gap_manifest_digest_invalid",
                length=64,
            ))
        version = exact_bounded_text(
            self.version, "attack_gap_version_invalid", maximum=128,
        )
        if version != ATTACK_GAP_ANALYSIS_VERSION:
            raise ValueError("attack_gap_version_invalid")
        object.__setattr__(self, "version", version)

    def _validate_counts(self) -> None:
        for field_name in self.__slots__:
            if field_name.endswith("_count"):
                object.__setattr__(self, field_name, exact_bounded_nonnegative_int(
                    object.__getattribute__(self, field_name),
                    "attack_gap_count_invalid",
                    maximum=1_000_000,
                ))
        if self.exact_count + self.partial_count + self.unsupported_count != len(
            self.analytics
        ):
            raise ValueError("attack_gap_classification_counts_invalid")

    def _validate_records(self) -> None:
        if type(self.analytics) is not tuple or len(self.analytics) > MAX_ANALYTIC_GAP_RECORDS:
            raise TypeError("attack_gap_analytics_invalid")
        if any(type(item) is not AttackAnalyticObservability for item in self.analytics):
            raise TypeError("attack_gap_analytics_invalid")
        if type(self.implementation_bindings) is not tuple or len(
            self.implementation_bindings
        ) > 4096:
            raise TypeError("attack_gap_bindings_invalid")
        if any(
            type(item) is not AttackImplementationBindingStatus
            for item in self.implementation_bindings
        ):
            raise TypeError("attack_gap_bindings_invalid")

    def _values(self) -> dict[str, object]:
        return {
            field: object.__getattribute__(self, field)
            for field in self.__slots__
            if field != "report_digest"
        }

    def to_record(self) -> dict[str, object]:
        return _report_record(self._values(), self.report_digest)


__all__ = (
    "ATTACK_BINDING_STATES",
    "ATTACK_GAP_ANALYSIS_VERSION",
    "ATTACK_GAP_CLASSIFICATIONS",
    "AttackAnalyticObservability",
    "AttackCapabilityGapReport",
    "AttackImplementationBindingStatus",
)
