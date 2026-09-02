"""Immutable multi-label independent-corpus contracts for ATT&CK evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path, PosixPath, WindowsPath

from Virus_Scan.contracts.numeric_boundaries import exact_bounded_nonnegative_int
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.detection.attack.implementations import ATTACK_ANALYTIC_CLAIM_SCOPES
from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.detection.attack.validation import (
    exact_hex,
    official_attack_id,
    ordered_text_tuple,
    stix_timestamp,
)

ATTACK_EVALUATION_CORPUS_VERSION = "stage2636_11008_attack_multilabel_corpus_v3"
ATTACK_EVALUATION_EVIDENCE_CLASSES = frozenset({
    "independent_external", "synthetic_development",
})
ATTACK_EVALUATION_EVIDENCE_DOMAINS = frozenset({
    "independent_external", "synthetic_engineering",
})
ATTACK_EVALUATION_REVIEW_STATES = frozenset({
    "independent_adjudicated", "artifact_byte_oracle",
})
ATTACK_EVALUATION_PARTITIONS = (
    "development", "future_time_holdout", "locked_holdout", "validation",
)
ATTACK_EVALUATION_EXPECTED_STATES = frozenset({
    "confirmed", "candidate", "rejected", "unavailable",
})
ATTACK_EVALUATION_MALWARE_CLASSES = frozenset({"malware", "control"})
ATTACK_EVALUATION_SAMPLE_CATEGORIES = frozenset({
    "malware_artifact",
    "clean_software",
    "packer_installer_updater",
    "administrative_or_dual_use",
    "benign_script_lookalike",
    "adjacent_technique_control",
    "corrupt_or_truncated",
    "unsupported_or_unavailable",
    "benign_yara_or_alias_collision",
})
ATTACK_EVALUATION_MODALITIES = frozenset({
    "static_string", "static_structure", "static_control_flow",
    "dynamic_runtime", "host_telemetry", "network_telemetry", "yara_match",
    "metadata", "derived", "unavailable",
})
_MAX_MANIFEST_BYTES = 512 * 1024 * 1024
_MAX_SAMPLES = 100_000
_MAX_EXPECTATIONS_PER_SAMPLE = 4_096
_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024 * 1024


def _plain_mapping(value: object, reason: str) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise TypeError(reason)
    return value


def _reject_constant(_value: str) -> object:
    raise ValueError("attack_evaluation_json_nonfinite")


def _load_json_no_duplicates(path: Path) -> dict[str, object]:
    if type(path) not in (PosixPath, WindowsPath):
        raise TypeError("attack_evaluation_manifest_path_invalid")
    if path_contains_filesystem_alias(path) or not path.is_file():
        raise ValueError("attack_evaluation_manifest_file_invalid")
    size = path.stat().st_size
    if size < 1 or size > _MAX_MANIFEST_BYTES:
        raise ValueError("attack_evaluation_manifest_size_invalid")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in items:
            if type(key) is not str or key in out:
                raise ValueError("attack_evaluation_json_duplicate_key")
            out[key] = value
        return out

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=pairs,
        parse_constant=_reject_constant,
    )
    return _plain_mapping(value, "attack_evaluation_manifest_invalid")


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


@dataclass(frozen=True, slots=True, order=True)
class AttackTechniqueExpectation:
    """One independent expected production outcome for one ATT&CK technique."""

    technique_id: str
    expected_state: str
    label_rationale: str
    label_evidence_refs: tuple[str, ...]
    supported_claim_scope: str
    platform: str
    modality: str

    def __post_init__(self) -> None:
        if type(self) is not AttackTechniqueExpectation:
            raise TypeError("attack_evaluation_expectation_owner_invalid")
        technique_id = official_attack_id(
            self.technique_id, "attack_evaluation_technique_invalid",
        )
        if not technique_id.startswith("T") or technique_id.startswith("TA"):
            raise ValueError("attack_evaluation_technique_invalid")
        expected_state = exact_bounded_text(
            self.expected_state,
            "attack_evaluation_expected_state_invalid",
            maximum=16,
        )
        if expected_state not in ATTACK_EVALUATION_EXPECTED_STATES:
            raise ValueError("attack_evaluation_expected_state_invalid")
        rationale = exact_bounded_text(
            self.label_rationale,
            "attack_evaluation_label_rationale_invalid",
            maximum=4096,
        )
        references = ordered_text_tuple(
            self.label_evidence_refs,
            "attack_evaluation_label_evidence_refs_invalid",
            maximum_items=128,
        )
        if expected_state != "unavailable" and not references:
            raise ValueError("attack_evaluation_label_evidence_refs_required")
        claim_scope = exact_bounded_text(
            self.supported_claim_scope,
            "attack_evaluation_claim_scope_invalid",
            maximum=32,
        )
        if claim_scope not in ATTACK_ANALYTIC_CLAIM_SCOPES:
            raise ValueError("attack_evaluation_claim_scope_invalid")
        platform = exact_bounded_text(
            self.platform,
            "attack_evaluation_platform_invalid",
            maximum=64,
        )
        modality = exact_bounded_text(
            self.modality,
            "attack_evaluation_modality_invalid",
            maximum=32,
        )
        if modality not in ATTACK_EVALUATION_MODALITIES:
            raise ValueError("attack_evaluation_modality_invalid")
        if expected_state == "unavailable":
            if claim_scope != "unavailable" or modality != "unavailable":
                raise ValueError("attack_evaluation_unavailable_scope_invalid")
        elif claim_scope == "unavailable" or modality == "unavailable":
            raise ValueError("attack_evaluation_available_scope_invalid")
        object.__setattr__(self, "technique_id", technique_id)
        object.__setattr__(self, "expected_state", expected_state)
        object.__setattr__(self, "label_rationale", rationale)
        object.__setattr__(self, "label_evidence_refs", references)
        object.__setattr__(self, "supported_claim_scope", claim_scope)
        object.__setattr__(self, "platform", platform)
        object.__setattr__(self, "modality", modality)

    @classmethod
    def from_record(cls, value: object) -> "AttackTechniqueExpectation":
        record = _plain_mapping(value, "attack_evaluation_expectation_invalid")
        expected = {
            "technique_id", "expected_state", "label_rationale",
            "label_evidence_refs", "supported_claim_scope", "platform", "modality",
        }
        if set(record) != expected:
            raise ValueError("attack_evaluation_expectation_fields_invalid")
        refs = dict.get(record, "label_evidence_refs")
        if type(refs) is not list:
            raise TypeError("attack_evaluation_label_evidence_refs_invalid")
        return cls(
            technique_id=dict.get(record, "technique_id"),
            expected_state=dict.get(record, "expected_state"),
            label_rationale=dict.get(record, "label_rationale"),
            label_evidence_refs=tuple(refs),
            supported_claim_scope=dict.get(record, "supported_claim_scope"),
            platform=dict.get(record, "platform"),
            modality=dict.get(record, "modality"),
        )

    def to_record(self) -> dict[str, object]:
        return {
            "technique_id": self.technique_id,
            "expected_state": self.expected_state,
            "label_rationale": self.label_rationale,
            "label_evidence_refs": self.label_evidence_refs,
            "supported_claim_scope": self.supported_claim_scope,
            "platform": self.platform,
            "modality": self.modality,
        }


@dataclass(frozen=True, slots=True, order=True)
class AttackEvaluationSample:
    """One independently reviewed raw artifact and its complete technique truth."""

    sample_id: str
    partition: str
    source_family: str
    related_group: str
    package_campaign_id: str
    collection_session: str
    malware_class: str
    sample_category: str
    artifact_path: str
    artifact_sha256: str
    artifact_size: int
    acquisition_provenance: str
    collected_at: str
    platform: str
    file_type: str
    technique_expectations: tuple[AttackTechniqueExpectation, ...]
    evidence_domain: str
    eligible_for_production_metrics: bool
    eligible_for_policy_promotion: bool
    eligible_for_production_calibration: bool
    scanner_boundary: str = "production_file_scan"

    def __post_init__(self) -> None:
        if type(self) is not AttackEvaluationSample:
            raise TypeError("attack_evaluation_sample_owner_invalid")
        text_fields = (
            ("sample_id", self.sample_id, 128, False),
            ("partition", self.partition, 32, False),
            ("source_family", self.source_family, 128, False),
            ("related_group", self.related_group, 128, False),
            ("package_campaign_id", self.package_campaign_id, 128, False),
            ("collection_session", self.collection_session, 128, False),
            ("malware_class", self.malware_class, 16, False),
            ("sample_category", self.sample_category, 64, False),
            ("artifact_path", self.artifact_path, 4096, False),
            ("acquisition_provenance", self.acquisition_provenance, 1024, False),
            ("platform", self.platform, 64, False),
            ("file_type", self.file_type, 128, False),
            ("evidence_domain", self.evidence_domain, 32, False),
            ("scanner_boundary", self.scanner_boundary, 64, False),
        )
        materialized: dict[str, str] = {}
        for name, value, maximum, allow_blank in text_fields:
            materialized[name] = exact_bounded_text(
                value,
                "attack_evaluation_" + name + "_invalid",
                maximum=maximum,
                allow_blank=allow_blank,
            )
        if materialized["partition"] not in ATTACK_EVALUATION_PARTITIONS:
            raise ValueError("attack_evaluation_partition_invalid")
        if materialized["malware_class"] not in ATTACK_EVALUATION_MALWARE_CLASSES:
            raise ValueError("attack_evaluation_malware_class_invalid")
        if materialized["sample_category"] not in ATTACK_EVALUATION_SAMPLE_CATEGORIES:
            raise ValueError("attack_evaluation_sample_category_invalid")
        if materialized["evidence_domain"] not in ATTACK_EVALUATION_EVIDENCE_DOMAINS:
            raise ValueError("attack_evaluation_evidence_domain_invalid")
        if materialized["scanner_boundary"] != "production_file_scan":
            raise ValueError("attack_evaluation_post_scanner_fixture_invalid")
        authority_flags = (
            self.eligible_for_production_metrics,
            self.eligible_for_policy_promotion,
            self.eligible_for_production_calibration,
        )
        if any(type(value) is not bool for value in authority_flags):
            raise TypeError("attack_evaluation_authority_flag_invalid")
        if materialized["evidence_domain"] == "synthetic_engineering" and any(authority_flags):
            raise ValueError("attack_evaluation_synthetic_authority_invalid")
        if (
            materialized["malware_class"] == "malware"
            and materialized["sample_category"] != "malware_artifact"
        ):
            raise ValueError("attack_evaluation_malware_category_invalid")
        if (
            materialized["malware_class"] == "control"
            and materialized["sample_category"] == "malware_artifact"
        ):
            raise ValueError("attack_evaluation_control_category_invalid")
        artifact_sha256 = exact_hex(
            self.artifact_sha256,
            "attack_evaluation_artifact_sha256_invalid",
            length=64,
        )
        artifact_size = exact_bounded_nonnegative_int(
            self.artifact_size,
            "attack_evaluation_artifact_size_invalid",
            maximum=_MAX_ARTIFACT_BYTES,
        )
        collected_at = stix_timestamp(
            self.collected_at, "attack_evaluation_collected_at_invalid",
        )
        if (
            type(self.technique_expectations) is not tuple
            or not self.technique_expectations
            or len(self.technique_expectations) > _MAX_EXPECTATIONS_PER_SAMPLE
            or any(
                type(item) is not AttackTechniqueExpectation
                for item in self.technique_expectations
            )
        ):
            raise TypeError("attack_evaluation_expectations_invalid")
        expectations = tuple(sorted(self.technique_expectations))
        if len({item.technique_id for item in expectations}) != len(expectations):
            raise ValueError("attack_evaluation_duplicate_technique_expectation")
        for name, value in materialized.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "artifact_sha256", artifact_sha256)
        object.__setattr__(self, "artifact_size", artifact_size)
        object.__setattr__(self, "collected_at", collected_at)
        object.__setattr__(self, "technique_expectations", expectations)

    @classmethod
    def from_record(cls, value: object) -> "AttackEvaluationSample":
        record = _plain_mapping(value, "attack_evaluation_sample_invalid")
        expected = {
            "sample_id", "partition", "source_family", "related_group",
            "package_campaign_id", "collection_session", "malware_class",
            "sample_category", "artifact_path", "artifact_sha256", "artifact_size",
            "acquisition_provenance", "collected_at", "platform", "file_type",
            "technique_expectations", "evidence_domain",
            "eligible_for_production_metrics", "eligible_for_policy_promotion",
            "eligible_for_production_calibration", "scanner_boundary",
        }
        if set(record) != expected:
            raise ValueError("attack_evaluation_sample_fields_invalid")
        raw_expectations = dict.get(record, "technique_expectations")
        if type(raw_expectations) is not list:
            raise TypeError("attack_evaluation_expectations_invalid")
        return cls(
            sample_id=dict.get(record, "sample_id"),
            partition=dict.get(record, "partition"),
            source_family=dict.get(record, "source_family"),
            related_group=dict.get(record, "related_group"),
            package_campaign_id=dict.get(record, "package_campaign_id"),
            collection_session=dict.get(record, "collection_session"),
            malware_class=dict.get(record, "malware_class"),
            sample_category=dict.get(record, "sample_category"),
            artifact_path=dict.get(record, "artifact_path"),
            artifact_sha256=dict.get(record, "artifact_sha256"),
            artifact_size=dict.get(record, "artifact_size"),
            acquisition_provenance=dict.get(record, "acquisition_provenance"),
            collected_at=dict.get(record, "collected_at"),
            platform=dict.get(record, "platform"),
            file_type=dict.get(record, "file_type"),
            technique_expectations=tuple(
                AttackTechniqueExpectation.from_record(item)
                for item in raw_expectations
            ),
            evidence_domain=dict.get(record, "evidence_domain"),
            eligible_for_production_metrics=dict.get(record, "eligible_for_production_metrics"),
            eligible_for_policy_promotion=dict.get(record, "eligible_for_policy_promotion"),
            eligible_for_production_calibration=dict.get(record, "eligible_for_production_calibration"),
            scanner_boundary=dict.get(record, "scanner_boundary"),
        )

    def to_record(self) -> dict[str, object]:
        return {
            "sample_id": self.sample_id,
            "partition": self.partition,
            "source_family": self.source_family,
            "related_group": self.related_group,
            "package_campaign_id": self.package_campaign_id,
            "collection_session": self.collection_session,
            "malware_class": self.malware_class,
            "sample_category": self.sample_category,
            "artifact_path": self.artifact_path,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size": self.artifact_size,
            "acquisition_provenance": self.acquisition_provenance,
            "collected_at": self.collected_at,
            "platform": self.platform,
            "file_type": self.file_type,
            "technique_expectations": tuple(
                item.to_record() for item in self.technique_expectations
            ),
            "evidence_domain": self.evidence_domain,
            "eligible_for_production_metrics": self.eligible_for_production_metrics,
            "eligible_for_policy_promotion": self.eligible_for_policy_promotion,
            "eligible_for_production_calibration": self.eligible_for_production_calibration,
            "scanner_boundary": self.scanner_boundary,
        }


@dataclass(frozen=True, slots=True, order=True)
class AttackEvaluationPartitionCount:
    """Declared exact malware/control counts for one corpus partition."""

    partition: str
    malware_count: int
    control_count: int

    def __post_init__(self) -> None:
        if type(self) is not AttackEvaluationPartitionCount:
            raise TypeError("attack_evaluation_partition_count_owner_invalid")
        partition = exact_bounded_text(
            self.partition, "attack_evaluation_partition_invalid", maximum=32,
        )
        if partition not in ATTACK_EVALUATION_PARTITIONS:
            raise ValueError("attack_evaluation_partition_invalid")
        object.__setattr__(self, "partition", partition)
        object.__setattr__(self, "malware_count", exact_bounded_nonnegative_int(
            self.malware_count,
            "attack_evaluation_partition_malware_count_invalid",
            maximum=_MAX_SAMPLES,
        ))
        object.__setattr__(self, "control_count", exact_bounded_nonnegative_int(
            self.control_count,
            "attack_evaluation_partition_control_count_invalid",
            maximum=_MAX_SAMPLES,
        ))

    @classmethod
    def from_record(cls, value: object) -> "AttackEvaluationPartitionCount":
        record = _plain_mapping(value, "attack_evaluation_partition_count_invalid")
        if set(record) != {"partition", "malware_count", "control_count"}:
            raise ValueError("attack_evaluation_partition_count_fields_invalid")
        return cls(
            partition=dict.get(record, "partition"),
            malware_count=dict.get(record, "malware_count"),
            control_count=dict.get(record, "control_count"),
        )

    def to_record(self) -> dict[str, object]:
        return {
            "partition": self.partition,
            "malware_count": self.malware_count,
            "control_count": self.control_count,
        }


@dataclass(frozen=True, slots=True)
class AttackEvaluationCorpusManifest:
    """One immutable independently reviewed, complete multi-label corpus manifest."""

    corpus_id: str
    corpus_version: str
    corpus_evidence_class: str
    label_review_status: str
    generation_policy_digest: str
    policy_version: str
    repository_version: str
    repository_digest: str
    policy_frozen_at: str
    frozen_at: str
    reviewer_ids: tuple[str, ...]
    adjudicator_ids: tuple[str, ...]
    reviewed_technique_ids: tuple[str, ...]
    partition_counts: tuple[AttackEvaluationPartitionCount, ...]
    samples: tuple[AttackEvaluationSample, ...]
    schema_version: str = ATTACK_EVALUATION_CORPUS_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttackEvaluationCorpusManifest:
            raise TypeError("attack_evaluation_corpus_owner_invalid")
        corpus_id = exact_bounded_text(
            self.corpus_id, "attack_evaluation_corpus_id_invalid", maximum=128,
        )
        corpus_version = exact_bounded_text(
            self.corpus_version,
            "attack_evaluation_corpus_identity_version_invalid",
            maximum=128,
        )
        evidence_class = exact_bounded_text(
            self.corpus_evidence_class,
            "attack_evaluation_evidence_class_invalid",
            maximum=32,
        )
        if evidence_class not in ATTACK_EVALUATION_EVIDENCE_CLASSES:
            raise ValueError("attack_evaluation_evidence_class_invalid")
        review_status = exact_bounded_text(
            self.label_review_status,
            "attack_evaluation_review_status_invalid",
            maximum=32,
        )
        if review_status not in ATTACK_EVALUATION_REVIEW_STATES:
            raise ValueError("attack_evaluation_review_status_invalid")
        generation_digest = exact_bounded_text(
            self.generation_policy_digest,
            "attack_evaluation_generation_digest_invalid",
            maximum=64,
            allow_blank=True,
        )
        if evidence_class == "synthetic_development":
            generation_digest = exact_hex(
                generation_digest,
                "attack_evaluation_generation_digest_invalid",
                length=64,
            )
            if review_status != "artifact_byte_oracle":
                raise ValueError("attack_evaluation_synthetic_review_status_invalid")
        elif generation_digest or review_status != "independent_adjudicated":
            raise ValueError("attack_evaluation_independent_review_status_invalid")
        policy_version = exact_bounded_text(
            self.policy_version, "attack_evaluation_policy_version_invalid", maximum=128,
        )
        repository_version = exact_bounded_text(
            self.repository_version,
            "attack_evaluation_repository_version_invalid",
            maximum=128,
        )
        repository_digest = exact_hex(
            self.repository_digest,
            "attack_evaluation_repository_digest_invalid",
            length=64,
        )
        policy_frozen_at = stix_timestamp(
            self.policy_frozen_at, "attack_evaluation_policy_frozen_at_invalid",
        )
        frozen_at = stix_timestamp(
            self.frozen_at, "attack_evaluation_frozen_at_invalid",
        )
        if _timestamp_value(frozen_at) < _timestamp_value(policy_frozen_at):
            raise ValueError("attack_evaluation_freeze_order_invalid")
        reviewers = ordered_text_tuple(
            self.reviewer_ids,
            "attack_evaluation_reviewers_invalid",
            maximum_items=256,
        )
        adjudicators = ordered_text_tuple(
            self.adjudicator_ids,
            "attack_evaluation_adjudicators_invalid",
            maximum_items=64,
        )
        if len(reviewers) < 2:
            raise ValueError("attack_evaluation_independent_reviewers_required")
        if not adjudicators:
            raise ValueError("attack_evaluation_adjudicator_required")
        if set(reviewers) & set(adjudicators):
            raise ValueError("attack_evaluation_review_adjudication_independence_invalid")
        raw_techniques = ordered_text_tuple(
            self.reviewed_technique_ids,
            "attack_evaluation_reviewed_techniques_invalid",
            maximum_items=_MAX_EXPECTATIONS_PER_SAMPLE,
        )
        if not raw_techniques:
            raise ValueError("attack_evaluation_reviewed_techniques_required")
        techniques = tuple(
            official_attack_id(item, "attack_evaluation_reviewed_techniques_invalid")
            for item in raw_techniques
        )
        if any(not item.startswith("T") or item.startswith("TA") for item in techniques):
            raise ValueError("attack_evaluation_reviewed_techniques_invalid")
        if (
            type(self.partition_counts) is not tuple
            or any(type(item) is not AttackEvaluationPartitionCount for item in self.partition_counts)
        ):
            raise TypeError("attack_evaluation_partition_counts_invalid")
        partition_counts = tuple(sorted(self.partition_counts))
        if tuple(item.partition for item in partition_counts) != ATTACK_EVALUATION_PARTITIONS:
            raise ValueError("attack_evaluation_partition_counts_incomplete")
        if type(self.samples) is not tuple or len(self.samples) > _MAX_SAMPLES:
            raise TypeError("attack_evaluation_samples_invalid")
        if any(type(item) is not AttackEvaluationSample for item in self.samples):
            raise TypeError("attack_evaluation_samples_invalid")
        samples = tuple(sorted(self.samples))
        if len({item.sample_id for item in samples}) != len(samples):
            raise ValueError("attack_evaluation_duplicate_sample")
        if len({item.artifact_sha256 for item in samples}) != len(samples):
            raise ValueError("attack_evaluation_duplicate_artifact_digest")
        if len({item.artifact_path for item in samples}) != len(samples):
            raise ValueError("attack_evaluation_duplicate_artifact_path")
        technique_set = set(techniques)
        for item in samples:
            if {expectation.technique_id for expectation in item.technique_expectations} != technique_set:
                raise ValueError("attack_evaluation_expectation_set_incomplete")
            if evidence_class == "synthetic_development":
                if item.evidence_domain != "synthetic_engineering":
                    raise ValueError("attack_evaluation_synthetic_domain_invalid")
                if (
                    item.eligible_for_production_metrics
                    or item.eligible_for_policy_promotion
                    or item.eligible_for_production_calibration
                ):
                    raise ValueError("attack_evaluation_synthetic_authority_invalid")
            elif item.evidence_domain != "independent_external":
                raise ValueError("attack_evaluation_independent_domain_invalid")
        actual_counts = {
            partition: {
                malware_class: sum(
                    item.partition == partition and item.malware_class == malware_class
                    for item in samples
                )
                for malware_class in ATTACK_EVALUATION_MALWARE_CLASSES
            }
            for partition in ATTACK_EVALUATION_PARTITIONS
        }
        for declared in partition_counts:
            actual = actual_counts[declared.partition]
            if (
                declared.malware_count != actual["malware"]
                or declared.control_count != actual["control"]
            ):
                raise ValueError("attack_evaluation_partition_count_mismatch")
        group_partitions: dict[tuple[str, str], str] = {}
        for item in samples:
            for dimension, identity in (
                ("source_family", item.source_family),
                ("related_group", item.related_group),
                ("package_campaign_id", item.package_campaign_id),
                ("collection_session", item.collection_session),
            ):
                key = (dimension, identity)
                prior = group_partitions.setdefault(key, item.partition)
                if prior != item.partition:
                    raise ValueError("attack_evaluation_source_group_leakage")
            collected = _timestamp_value(item.collected_at)
            policy_freeze = _timestamp_value(policy_frozen_at)
            if item.partition == "future_time_holdout":
                if collected <= policy_freeze:
                    raise ValueError("attack_evaluation_future_time_invalid")
            elif collected > policy_freeze:
                raise ValueError("attack_evaluation_nonfuture_time_invalid")
            if collected > _timestamp_value(frozen_at):
                raise ValueError("attack_evaluation_sample_after_manifest_freeze")
        schema_version = exact_bounded_text(
            self.schema_version,
            "attack_evaluation_corpus_version_invalid",
            maximum=128,
        )
        if schema_version != ATTACK_EVALUATION_CORPUS_VERSION:
            raise ValueError("attack_evaluation_corpus_version_invalid")
        object.__setattr__(self, "corpus_id", corpus_id)
        object.__setattr__(self, "corpus_version", corpus_version)
        object.__setattr__(self, "corpus_evidence_class", evidence_class)
        object.__setattr__(self, "label_review_status", review_status)
        object.__setattr__(self, "generation_policy_digest", generation_digest)
        object.__setattr__(self, "policy_version", policy_version)
        object.__setattr__(self, "repository_version", repository_version)
        object.__setattr__(self, "repository_digest", repository_digest)
        object.__setattr__(self, "policy_frozen_at", policy_frozen_at)
        object.__setattr__(self, "frozen_at", frozen_at)
        object.__setattr__(self, "reviewer_ids", reviewers)
        object.__setattr__(self, "adjudicator_ids", adjudicators)
        object.__setattr__(self, "reviewed_technique_ids", techniques)
        object.__setattr__(self, "partition_counts", partition_counts)
        object.__setattr__(self, "samples", samples)
        object.__setattr__(self, "schema_version", schema_version)

    @classmethod
    def from_path(cls, path: Path) -> "AttackEvaluationCorpusManifest":
        record = _load_json_no_duplicates(path)
        expected = {
            "corpus_id", "corpus_version", "corpus_evidence_class",
            "label_review_status", "generation_policy_digest", "policy_version",
            "repository_version",
            "repository_digest", "policy_frozen_at", "frozen_at", "reviewer_ids",
            "adjudicator_ids", "reviewed_technique_ids", "partition_counts",
            "samples", "schema_version",
        }
        if set(record) != expected:
            raise ValueError("attack_evaluation_manifest_fields_invalid")
        sequence_fields = (
            "reviewer_ids", "adjudicator_ids", "reviewed_technique_ids",
            "partition_counts", "samples",
        )
        if any(type(dict.get(record, field)) is not list for field in sequence_fields):
            raise TypeError("attack_evaluation_manifest_sequence_invalid")
        return cls(
            corpus_id=dict.get(record, "corpus_id"),
            corpus_version=dict.get(record, "corpus_version"),
            corpus_evidence_class=dict.get(record, "corpus_evidence_class"),
            label_review_status=dict.get(record, "label_review_status"),
            generation_policy_digest=dict.get(record, "generation_policy_digest"),
            policy_version=dict.get(record, "policy_version"),
            repository_version=dict.get(record, "repository_version"),
            repository_digest=dict.get(record, "repository_digest"),
            policy_frozen_at=dict.get(record, "policy_frozen_at"),
            frozen_at=dict.get(record, "frozen_at"),
            reviewer_ids=tuple(dict.get(record, "reviewer_ids")),
            adjudicator_ids=tuple(dict.get(record, "adjudicator_ids")),
            reviewed_technique_ids=tuple(dict.get(record, "reviewed_technique_ids")),
            partition_counts=tuple(
                AttackEvaluationPartitionCount.from_record(item)
                for item in dict.get(record, "partition_counts")
            ),
            samples=tuple(
                AttackEvaluationSample.from_record(item)
                for item in dict.get(record, "samples")
            ),
            schema_version=dict.get(record, "schema_version"),
        )

    @property
    def malware_sample_count(self) -> int:
        return sum(item.malware_count for item in self.partition_counts)

    @property
    def control_sample_count(self) -> int:
        return sum(item.control_count for item in self.partition_counts)

    def to_record(self) -> dict[str, object]:
        return {
            "corpus_id": self.corpus_id,
            "corpus_version": self.corpus_version,
            "corpus_evidence_class": self.corpus_evidence_class,
            "label_review_status": self.label_review_status,
            "generation_policy_digest": self.generation_policy_digest,
            "policy_version": self.policy_version,
            "repository_version": self.repository_version,
            "repository_digest": self.repository_digest,
            "policy_frozen_at": self.policy_frozen_at,
            "frozen_at": self.frozen_at,
            "reviewer_ids": self.reviewer_ids,
            "adjudicator_ids": self.adjudicator_ids,
            "reviewed_technique_ids": self.reviewed_technique_ids,
            "partition_counts": tuple(item.to_record() for item in self.partition_counts),
            "samples": tuple(item.to_record() for item in self.samples),
            "schema_version": self.schema_version,
        }

    @property
    def digest(self) -> str:
        payload = json.dumps(
            self.to_record(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        return sha256(payload).hexdigest()


__all__ = (
    "ATTACK_EVALUATION_CORPUS_VERSION",
    "ATTACK_EVALUATION_EVIDENCE_CLASSES",
    "ATTACK_EVALUATION_EVIDENCE_DOMAINS",
    "ATTACK_EVALUATION_EXPECTED_STATES",
    "ATTACK_EVALUATION_MALWARE_CLASSES",
    "ATTACK_EVALUATION_MODALITIES",
    "ATTACK_EVALUATION_PARTITIONS",
    "ATTACK_EVALUATION_REVIEW_STATES",
    "ATTACK_EVALUATION_SAMPLE_CATEGORIES",
    "AttackEvaluationCorpusManifest",
    "AttackEvaluationPartitionCount",
    "AttackEvaluationSample",
    "AttackTechniqueExpectation",
)
