"""Canonical immutable physical YARA evidence contracts.

This module owns collision-resistant rule identity, physical hit identity, and
one bounded scan-result schema.  It does not scan, load, compile, or interpret
YARA evidence as malware families or ATT&CK techniques.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.contracts.detection_observation import ObservationSourceLocation
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_plain_instance_dict,
    no_hook_text,
)

ANALYTICAL_EVIDENCE_SCHEMA_VERSION = 1
YARA_CALIBRATION_VERSION = 1
YARA_HIT_TEXT_UNAVAILABLE = "yara_hit_text_unavailable"
YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE = "yara_hit_normalization_failure_evidence"

YARA_RULE_IDENTITY_SCHEMA_VERSION = "stage2636_11008_yara_rule_identity_v1"
YARA_HIT_SCHEMA_VERSION = "stage2636_11008_yara_hit_v1"
YARA_SCAN_RESULT_SCHEMA_VERSION = "stage2636_11008_yara_scan_result_v1"

_YARA_INTEGRITY_STATES = frozenset({"verified", "unverified", "unavailable"})
_YARA_SOURCE_TRUST_STATES = frozenset({
    "official_verified", "custom_verified", "custom_unverified", "unavailable",
})
_YARA_PACKAGE_KINDS = frozenset({"core", "extended", "custom", "unavailable"})
_YARA_SCAN_STATUSES = frozenset({
    "complete", "complete_no_match", "disabled", "unavailable", "failed",
    "partial", "truncated",
})
_MAX_RULE_TAGS = 32
_MAX_SCAN_HITS = 256
_MAX_FAILURE_REASONS = 64


def _optional_yara_text(value: object, reason: str, *, maximum: int = 4096) -> str:
    return exact_bounded_text(value, reason, maximum=maximum, allow_blank=True)


def _sha256_or_blank(value: object, reason: str) -> str:
    text = _optional_yara_text(value, reason, maximum=64)
    if text != "" and (len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text)):
        raise ValueError(reason)
    return text


def _bounded_sorted_text_tuple(
    value: object,
    *,
    reason: str,
    item_reason: str,
    maximum_items: int,
    maximum_text: int,
) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > maximum_items:
        raise TypeError(reason)
    items = tuple(
        exact_bounded_text(item, item_reason, maximum=maximum_text)
        for item in value
    )
    if items != tuple(sorted(set(items))):
        raise ValueError(reason)
    return items


@dataclass(frozen=True, slots=True, order=True)
class YaraRuleIdentity:
    """Collision-resistant identity for the exact rule definition that matched."""

    package_kind: str
    rule_source_digest: str
    compiled_cache_digest: str
    rule_catalog_digest: str
    source_member: str
    compiler_namespace: str
    rule_name: str
    metadata_id: str = ""
    logic_hash: str = ""
    semantic_metadata_digest: str = ""
    rule_tags: tuple[str, ...] = ()
    schema_version: str = YARA_RULE_IDENTITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not YaraRuleIdentity:
            raise TypeError("yara_rule_identity_owner_invalid")
        kind = exact_bounded_text(self.package_kind, "yara_rule_package_kind_invalid", maximum=32)
        if kind not in _YARA_PACKAGE_KINDS:
            raise ValueError("yara_rule_package_kind_invalid")
        source_digest = _sha256_or_blank(self.rule_source_digest, "yara_rule_source_digest_invalid")
        cache_digest = _sha256_or_blank(self.compiled_cache_digest, "yara_rule_cache_digest_invalid")
        catalog_digest = _sha256_or_blank(self.rule_catalog_digest, "yara_rule_catalog_digest_invalid")
        source_member = _optional_yara_text(self.source_member, "yara_rule_source_member_invalid", maximum=4096)
        namespace = _optional_yara_text(self.compiler_namespace, "yara_rule_namespace_invalid", maximum=160)
        rule_name = exact_bounded_text(self.rule_name, "yara_rule_name_invalid", maximum=160)
        metadata_id = _optional_yara_text(self.metadata_id, "yara_rule_metadata_id_invalid", maximum=160)
        logic_hash = _sha256_or_blank(self.logic_hash, "yara_rule_logic_hash_invalid")
        metadata_digest = _sha256_or_blank(
            self.semantic_metadata_digest, "yara_rule_semantic_metadata_digest_invalid"
        )
        tags = _bounded_sorted_text_tuple(
            self.rule_tags,
            reason="yara_rule_tags_invalid",
            item_reason="yara_rule_tag_invalid",
            maximum_items=_MAX_RULE_TAGS,
            maximum_text=128,
        )
        schema = exact_bounded_text(self.schema_version, "yara_rule_identity_schema_invalid", maximum=128)
        if schema != YARA_RULE_IDENTITY_SCHEMA_VERSION:
            raise ValueError("yara_rule_identity_schema_version_unsupported")
        verified_identity = bool(source_digest and cache_digest and catalog_digest)
        if verified_identity:
            if kind == "unavailable" or not source_member or not namespace:
                raise ValueError("verified_yara_rule_identity_incomplete")
        elif any((source_digest, cache_digest, catalog_digest)):
            raise ValueError("partial_yara_rule_provenance_rejected")
        object.__setattr__(self, "package_kind", kind)
        object.__setattr__(self, "rule_source_digest", source_digest)
        object.__setattr__(self, "compiled_cache_digest", cache_digest)
        object.__setattr__(self, "rule_catalog_digest", catalog_digest)
        object.__setattr__(self, "source_member", source_member)
        object.__setattr__(self, "compiler_namespace", namespace)
        object.__setattr__(self, "rule_name", rule_name)
        object.__setattr__(self, "metadata_id", metadata_id)
        object.__setattr__(self, "logic_hash", logic_hash)
        object.__setattr__(self, "semantic_metadata_digest", metadata_digest)
        object.__setattr__(self, "rule_tags", tags)
        object.__setattr__(self, "schema_version", schema)

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_record())

    @property
    def verified_source_bound(self) -> bool:
        return bool(
            self.rule_source_digest
            and self.compiled_cache_digest
            and self.rule_catalog_digest
            and self.source_member
            and self.compiler_namespace
        )

    @property
    def mapping_eligible(self) -> bool:
        return self.verified_source_bound and bool(self.logic_hash and self.semantic_metadata_digest)

    def to_record(self) -> dict[str, object]:
        return {
            "compiled_cache_digest": self.compiled_cache_digest,
            "compiler_namespace": self.compiler_namespace,
            "logic_hash": self.logic_hash,
            "metadata_id": self.metadata_id,
            "package_kind": self.package_kind,
            "rule_catalog_digest": self.rule_catalog_digest,
            "rule_name": self.rule_name,
            "rule_source_digest": self.rule_source_digest,
            "rule_tags": self.rule_tags,
            "schema_version": self.schema_version,
            "semantic_metadata_digest": self.semantic_metadata_digest,
            "source_member": self.source_member,
        }

    @classmethod
    def from_record(cls, value: object) -> "YaraRuleIdentity":
        if type(value) is not dict:
            raise TypeError("yara_rule_identity_record_invalid")
        expected = {
            "compiled_cache_digest", "compiler_namespace", "logic_hash",
            "metadata_id", "package_kind", "rule_catalog_digest", "rule_name",
            "rule_source_digest", "rule_tags", "schema_version",
            "semantic_metadata_digest", "source_member",
        }
        if set(value) != expected:
            raise ValueError("yara_rule_identity_record_fields_invalid")
        raw_tags = dict.get(value, "rule_tags")
        if type(raw_tags) not in (tuple, list):
            raise TypeError("yara_rule_identity_record_tags_invalid")
        return cls(
            package_kind=dict.get(value, "package_kind"),
            rule_source_digest=dict.get(value, "rule_source_digest"),
            compiled_cache_digest=dict.get(value, "compiled_cache_digest"),
            rule_catalog_digest=dict.get(value, "rule_catalog_digest"),
            source_member=dict.get(value, "source_member"),
            compiler_namespace=dict.get(value, "compiler_namespace"),
            rule_name=dict.get(value, "rule_name"),
            metadata_id=dict.get(value, "metadata_id"),
            logic_hash=dict.get(value, "logic_hash"),
            semantic_metadata_digest=dict.get(value, "semantic_metadata_digest"),
            rule_tags=tuple(raw_tags),
            schema_version=dict.get(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True, order=True)
class YaraHit:
    """Physical integrity-bearing YARA match fact without semantic interpretation."""

    rule_identity: YaraRuleIdentity
    root_observation_id: str
    integrity_status: str
    source_trust: str
    release_id: int
    release_tag: str
    compile_policy_version: str
    artifact_identity: str
    source_location: ObservationSourceLocation
    unavailable_reason: str = ""
    schema_version: str = YARA_HIT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not YaraHit or type(self.rule_identity) is not YaraRuleIdentity:
            raise TypeError("yara_hit_owner_invalid")
        root = exact_bounded_text(self.root_observation_id, "yara_hit_root_invalid", maximum=128)
        if not root.startswith("obs_"):
            raise ValueError("yara_hit_root_invalid")
        integrity = exact_bounded_text(self.integrity_status, "yara_hit_integrity_invalid", maximum=32)
        if integrity not in _YARA_INTEGRITY_STATES:
            raise ValueError("yara_hit_integrity_invalid")
        trust = exact_bounded_text(self.source_trust, "yara_hit_source_trust_invalid", maximum=32)
        if trust not in _YARA_SOURCE_TRUST_STATES:
            raise ValueError("yara_hit_source_trust_invalid")
        if type(self.release_id) is not int or type(self.release_id) is bool or not 0 <= self.release_id <= 2**63 - 1:
            raise TypeError("yara_hit_release_id_invalid")
        release_tag = _optional_yara_text(self.release_tag, "yara_hit_release_tag_invalid", maximum=128)
        policy = exact_bounded_text(
            self.compile_policy_version, "yara_hit_compile_policy_version_invalid", maximum=128
        )
        artifact = _optional_yara_text(self.artifact_identity, "yara_hit_artifact_invalid")
        if type(self.source_location) is not ObservationSourceLocation:
            raise TypeError("yara_hit_source_location_invalid")
        unavailable = _optional_yara_text(self.unavailable_reason, "yara_hit_unavailable_reason_invalid", maximum=512)
        schema = exact_bounded_text(self.schema_version, "yara_hit_schema_version_invalid", maximum=128)
        if schema != YARA_HIT_SCHEMA_VERSION:
            raise ValueError("yara_hit_schema_version_unsupported")
        verified = integrity == "verified"
        if verified:
            if trust not in ("official_verified", "custom_verified"):
                raise ValueError("verified_yara_hit_trust_required")
            if not self.rule_identity.verified_source_bound:
                raise ValueError("verified_yara_hit_rule_identity_required")
            if not artifact or not self.source_location.identifies_physical_source or unavailable:
                raise ValueError("verified_yara_hit_physical_identity_required")
        if integrity == "unavailable" and not unavailable:
            raise ValueError("unavailable_yara_hit_reason_required")
        object.__setattr__(self, "root_observation_id", root)
        object.__setattr__(self, "integrity_status", integrity)
        object.__setattr__(self, "source_trust", trust)
        object.__setattr__(self, "release_tag", release_tag)
        object.__setattr__(self, "compile_policy_version", policy)
        object.__setattr__(self, "artifact_identity", artifact)
        object.__setattr__(self, "unavailable_reason", unavailable)
        object.__setattr__(self, "schema_version", schema)

    @property
    def verified(self) -> bool:
        return self.integrity_status == "verified"

    def to_record(self) -> dict[str, object]:
        return {
            "artifact_identity": self.artifact_identity,
            "compile_policy_version": self.compile_policy_version,
            "integrity_status": self.integrity_status,
            "release_id": self.release_id,
            "release_tag": self.release_tag,
            "root_observation_id": self.root_observation_id,
            "rule_identity": self.rule_identity.to_record(),
            "schema_version": self.schema_version,
            "source_location": self.source_location.to_record(),
            "source_trust": self.source_trust,
            "unavailable_reason": self.unavailable_reason,
        }

    @classmethod
    def from_record(cls, value: object) -> "YaraHit":
        if type(value) is not dict:
            raise TypeError("yara_hit_record_invalid")
        expected = {
            "artifact_identity", "compile_policy_version", "integrity_status",
            "release_id", "release_tag", "root_observation_id", "rule_identity",
            "schema_version", "source_location", "source_trust", "unavailable_reason",
        }
        if set(value) != expected:
            raise ValueError("yara_hit_record_fields_invalid")
        return cls(
            rule_identity=YaraRuleIdentity.from_record(dict.get(value, "rule_identity")),
            root_observation_id=dict.get(value, "root_observation_id"),
            integrity_status=dict.get(value, "integrity_status"),
            source_trust=dict.get(value, "source_trust"),
            release_id=dict.get(value, "release_id"),
            release_tag=dict.get(value, "release_tag"),
            compile_policy_version=dict.get(value, "compile_policy_version"),
            artifact_identity=dict.get(value, "artifact_identity"),
            source_location=ObservationSourceLocation.from_record(dict.get(value, "source_location")),
            unavailable_reason=dict.get(value, "unavailable_reason"),
            schema_version=dict.get(value, "schema_version"),
        )


def canonical_yara_hit_sequence(value: object) -> tuple[tuple[YaraHit, ...], int]:
    """Return one collision-checked deterministic physical-hit sequence."""
    if type(value) is not tuple or any(type(item) is not YaraHit for item in value):
        raise TypeError("yara_hit_sequence_invalid")
    unique: dict[tuple[str, str], YaraHit] = {}
    for hit in value:
        key = (hit.root_observation_id, hit.rule_identity.digest)
        existing = unique.get(key)
        if existing is not None and existing != hit:
            raise ValueError("yara_hit_identity_collision")
        unique[key] = hit
    ordered = tuple(sorted(unique.values()))
    return ordered, len(value) - len(ordered)


@dataclass(frozen=True, slots=True)
class YaraScanResult:
    """One immutable bounded result for one physical YARA scan request."""

    status: str
    scan_pass_id: str
    physical_target_identity: str
    package_kind: str
    rule_source_digest: str
    compiled_cache_digest: str
    rule_catalog_digest: str
    hits: tuple[YaraHit, ...]
    total_match_count: int
    retained_match_count: int
    duplicate_match_count: int
    truncated_match_count: int
    archive_member_count: int
    scanned_member_count: int
    failed_member_count: int
    failure_reasons: tuple[str, ...] = ()
    unavailable_reason: str = ""
    schema_version: str = YARA_SCAN_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not YaraScanResult:
            raise TypeError("yara_scan_result_owner_invalid")
        status = exact_bounded_text(self.status, "yara_scan_status_invalid", maximum=32)
        if status not in _YARA_SCAN_STATUSES:
            raise ValueError("yara_scan_status_invalid")
        scan_pass = exact_bounded_text(self.scan_pass_id, "yara_scan_pass_id_invalid", maximum=128)
        if not scan_pass.startswith("yscan_"):
            raise ValueError("yara_scan_pass_id_invalid")
        target = _optional_yara_text(self.physical_target_identity, "yara_scan_target_identity_invalid")
        kind = exact_bounded_text(self.package_kind, "yara_scan_package_kind_invalid", maximum=32)
        if kind not in _YARA_PACKAGE_KINDS:
            raise ValueError("yara_scan_package_kind_invalid")
        source_digest = _sha256_or_blank(self.rule_source_digest, "yara_scan_source_digest_invalid")
        cache_digest = _sha256_or_blank(self.compiled_cache_digest, "yara_scan_cache_digest_invalid")
        catalog_digest = _sha256_or_blank(self.rule_catalog_digest, "yara_scan_catalog_digest_invalid")
        if type(self.hits) is not tuple or len(self.hits) > _MAX_SCAN_HITS or any(type(item) is not YaraHit for item in self.hits):
            raise TypeError("yara_scan_hits_invalid")
        ordered = tuple(sorted(set(self.hits)))
        if self.hits != ordered:
            raise ValueError("yara_scan_hits_order_invalid")
        counts: list[int] = []
        for value, reason in (
            (self.total_match_count, "yara_scan_total_count_invalid"),
            (self.retained_match_count, "yara_scan_retained_count_invalid"),
            (self.duplicate_match_count, "yara_scan_duplicate_count_invalid"),
            (self.truncated_match_count, "yara_scan_truncated_count_invalid"),
            (self.archive_member_count, "yara_scan_archive_member_count_invalid"),
            (self.scanned_member_count, "yara_scan_scanned_member_count_invalid"),
            (self.failed_member_count, "yara_scan_failed_member_count_invalid"),
        ):
            if type(value) is not int or type(value) is bool or value < 0 or value > 2**31 - 1:
                raise TypeError(reason)
            counts.append(value)
        total, retained, duplicates, truncated, members, scanned, failed = counts
        if retained != len(self.hits) or retained + duplicates + truncated > total:
            raise ValueError("yara_scan_match_counts_inconsistent")
        if scanned + failed > members:
            raise ValueError("yara_scan_member_counts_inconsistent")
        reasons = _bounded_sorted_text_tuple(
            self.failure_reasons,
            reason="yara_scan_failure_reasons_invalid",
            item_reason="yara_scan_failure_reason_invalid",
            maximum_items=_MAX_FAILURE_REASONS,
            maximum_text=256,
        )
        unavailable = _optional_yara_text(self.unavailable_reason, "yara_scan_unavailable_reason_invalid", maximum=512)
        schema = exact_bounded_text(self.schema_version, "yara_scan_schema_version_invalid", maximum=128)
        if schema != YARA_SCAN_RESULT_SCHEMA_VERSION:
            raise ValueError("yara_scan_schema_version_unsupported")
        if status == "complete" and not self.hits:
            raise ValueError("yara_scan_complete_hits_required")
        if status == "complete_no_match" and (self.hits or total != 0):
            raise ValueError("yara_scan_no_match_state_invalid")
        if status in ("disabled", "unavailable", "failed"):
            if self.hits or total != 0 or not unavailable:
                raise ValueError("yara_scan_terminal_unavailable_state_invalid")
        if status == "truncated" and truncated < 1:
            raise ValueError("yara_scan_truncated_state_invalid")
        if status == "partial" and not reasons and failed == 0:
            raise ValueError("yara_scan_partial_reason_required")
        if status in ("complete", "complete_no_match") and (reasons or unavailable or failed or truncated):
            raise ValueError("yara_scan_complete_state_contaminated")
        if status in ("complete", "complete_no_match", "partial", "truncated") and not target:
            raise ValueError("yara_scan_execution_identity_required")
        if any((source_digest, cache_digest, catalog_digest)) and not all((source_digest, cache_digest, catalog_digest)):
            raise ValueError("yara_scan_partial_provenance_rejected")
        if source_digest and kind == "unavailable":
            raise ValueError("yara_scan_package_identity_required")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "scan_pass_id", scan_pass)
        object.__setattr__(self, "physical_target_identity", target)
        object.__setattr__(self, "package_kind", kind)
        object.__setattr__(self, "rule_source_digest", source_digest)
        object.__setattr__(self, "compiled_cache_digest", cache_digest)
        object.__setattr__(self, "rule_catalog_digest", catalog_digest)
        object.__setattr__(self, "failure_reasons", reasons)
        object.__setattr__(self, "unavailable_reason", unavailable)
        object.__setattr__(self, "schema_version", schema)

    @property
    def complete(self) -> bool:
        return self.status in ("complete", "complete_no_match")

    @property
    def verified(self) -> bool:
        return bool(
            self.complete
            and self.rule_source_digest
            and self.compiled_cache_digest
            and self.rule_catalog_digest
            and all(hit.verified for hit in self.hits)
        )

    @property
    def semantic_digest(self) -> str:
        return canonical_json_sha256(self.to_record())

    def to_record(self) -> dict[str, object]:
        return {
            "archive_member_count": self.archive_member_count,
            "compiled_cache_digest": self.compiled_cache_digest,
            "duplicate_match_count": self.duplicate_match_count,
            "failed_member_count": self.failed_member_count,
            "failure_reasons": self.failure_reasons,
            "hits": tuple(hit.to_record() for hit in self.hits),
            "package_kind": self.package_kind,
            "physical_target_identity": self.physical_target_identity,
            "retained_match_count": self.retained_match_count,
            "rule_catalog_digest": self.rule_catalog_digest,
            "rule_source_digest": self.rule_source_digest,
            "scan_pass_id": self.scan_pass_id,
            "scanned_member_count": self.scanned_member_count,
            "schema_version": self.schema_version,
            "status": self.status,
            "total_match_count": self.total_match_count,
            "truncated_match_count": self.truncated_match_count,
            "unavailable_reason": self.unavailable_reason,
        }

    @classmethod
    def from_record(cls, value: object) -> "YaraScanResult":
        if type(value) is not dict:
            raise TypeError("yara_scan_result_record_invalid")
        expected = {
            "archive_member_count", "compiled_cache_digest", "duplicate_match_count",
            "failed_member_count", "failure_reasons", "hits", "package_kind",
            "physical_target_identity", "retained_match_count", "rule_catalog_digest",
            "rule_source_digest", "scan_pass_id", "scanned_member_count",
            "schema_version", "status", "total_match_count", "truncated_match_count",
            "unavailable_reason",
        }
        if set(value) != expected:
            raise ValueError("yara_scan_result_record_fields_invalid")
        raw_hits = dict.get(value, "hits")
        raw_reasons = dict.get(value, "failure_reasons")
        if type(raw_hits) not in (tuple, list) or type(raw_reasons) not in (tuple, list):
            raise TypeError("yara_scan_result_sequences_invalid")
        return cls(
            status=dict.get(value, "status"),
            scan_pass_id=dict.get(value, "scan_pass_id"),
            physical_target_identity=dict.get(value, "physical_target_identity"),
            package_kind=dict.get(value, "package_kind"),
            rule_source_digest=dict.get(value, "rule_source_digest"),
            compiled_cache_digest=dict.get(value, "compiled_cache_digest"),
            rule_catalog_digest=dict.get(value, "rule_catalog_digest"),
            hits=tuple(YaraHit.from_record(item) for item in raw_hits),
            total_match_count=dict.get(value, "total_match_count"),
            retained_match_count=dict.get(value, "retained_match_count"),
            duplicate_match_count=dict.get(value, "duplicate_match_count"),
            truncated_match_count=dict.get(value, "truncated_match_count"),
            archive_member_count=dict.get(value, "archive_member_count"),
            scanned_member_count=dict.get(value, "scanned_member_count"),
            failed_member_count=dict.get(value, "failed_member_count"),
            failure_reasons=tuple(raw_reasons),
            unavailable_reason=dict.get(value, "unavailable_reason"),
            schema_version=dict.get(value, "schema_version"),
        )


def merge_yara_scan_results(
    results: object,
    *,
    physical_target_identity: str,
) -> YaraScanResult:
    """Merge per-member results under one archive scan pass and identity."""
    if type(results) is not tuple or not results or any(type(item) is not YaraScanResult for item in results):
        raise TypeError("yara_scan_merge_results_invalid")
    target = exact_bounded_text(
        physical_target_identity, "yara_scan_merge_target_invalid", maximum=4096
    )
    identities = {
        (item.package_kind, item.rule_source_digest, item.compiled_cache_digest, item.rule_catalog_digest)
        for item in results
        if item.status not in ("disabled", "unavailable", "failed")
    }
    if len(identities) != 1:
        raise ValueError("yara_scan_merge_identity_mismatch")
    package_kind, source_digest, cache_digest, catalog_digest = next(iter(identities))
    all_hits = tuple(hit for item in results for hit in item.hits)
    ordered, merge_duplicates = canonical_yara_hit_sequence(all_hits)
    retained = ordered[:_MAX_SCAN_HITS]
    merge_truncated = max(0, len(ordered) - len(retained))
    reasons = {reason for item in results for reason in item.failure_reasons}
    unavailable_reasons = {
        item.unavailable_reason for item in results if item.unavailable_reason
    }
    failed_members = sum(
        1 for item in results if item.status in ("failed", "unavailable", "partial")
    )
    truncated = sum(item.truncated_match_count for item in results) + merge_truncated
    if truncated:
        status = "truncated"
        reasons.add("yara_archive_result_truncated")
    elif failed_members or unavailable_reasons:
        status = "partial"
        reasons.update(unavailable_reasons)
    elif retained:
        status = "complete"
    else:
        status = "complete_no_match"
    scan_pass = "yscan_" + canonical_json_sha256({
        "member_scan_passes": tuple(item.scan_pass_id for item in results),
        "physical_target_identity": target,
    })
    return YaraScanResult(
        status=status,
        scan_pass_id=scan_pass,
        physical_target_identity=target,
        package_kind=package_kind,
        rule_source_digest=source_digest,
        compiled_cache_digest=cache_digest,
        rule_catalog_digest=catalog_digest,
        hits=retained,
        total_match_count=sum(item.total_match_count for item in results),
        retained_match_count=len(retained),
        duplicate_match_count=sum(item.duplicate_match_count for item in results) + merge_duplicates,
        truncated_match_count=truncated,
        archive_member_count=len(results),
        scanned_member_count=len(results) - failed_members,
        failed_member_count=failed_members,
        failure_reasons=tuple(sorted(reasons)),
    )


def unavailable_yara_scan_result(reason: str, *, status: str = "unavailable") -> YaraScanResult:
    reason_text = exact_bounded_text(reason, "yara_scan_unavailable_reason_invalid", maximum=512)
    if status not in ("disabled", "unavailable", "failed"):
        raise ValueError("yara_scan_unavailable_status_invalid")
    digest = canonical_json_sha256({"reason": reason_text, "status": status})
    return YaraScanResult(
        status=status,
        scan_pass_id="yscan_" + digest,
        physical_target_identity="",
        package_kind="unavailable",
        rule_source_digest="",
        compiled_cache_digest="",
        rule_catalog_digest="",
        hits=(),
        total_match_count=0,
        retained_match_count=0,
        duplicate_match_count=0,
        truncated_match_count=0,
        archive_member_count=0,
        scanned_member_count=0,
        failed_member_count=0,
        unavailable_reason=reason_text,
    )


def canonical_yara_scan_result(value: object) -> YaraScanResult:
    if type(value) is YaraScanResult:
        return value
    if type(value) is dict:
        try:
            return YaraScanResult.from_record(value)
        except (TypeError, ValueError):
            return unavailable_yara_scan_result("yara_scan_result_invalid")
    return unavailable_yara_scan_result("yara_scan_result_invalid")


def canonical_yara_hits(value: object) -> tuple[YaraHit, ...]:
    return canonical_yara_scan_result(value).hits


def yara_hit_records(value: object) -> tuple[dict[str, object], ...]:
    return tuple(hit.to_record() for hit in canonical_yara_hits(value))


def yara_scan_result_record(value: object) -> dict[str, object]:
    return canonical_yara_scan_result(value).to_record()


_YARA_TEXT_ATTRS = ("rule", "name", "id", "text", "value")
_YARA_MISSING_VALUE = object()
_YARA_SEQUENCE_FAILURE = object()


def _plain_yara_attr(value: object, attr: str) -> object:
    data = no_hook_plain_instance_dict(value)
    if data is not None and attr in data:
        return dict.__getitem__(data, attr)
    try:
        class_dict = type.__getattribute__(type(value), "__dict__")
    except (AttributeError, TypeError):
        return _YARA_MISSING_VALUE
    raw = class_dict.get(attr)
    if isinstance(raw, (str, bytes, bytearray, memoryview, int, float, bool)):
        return raw
    return _YARA_MISSING_VALUE


def _detached_yara_text(value: object) -> tuple[str, str]:
    if value is None:
        return "", "missing_yara_hit_text"
    try:
        text, reason = no_hook_text(
            value,
            missing_reason="missing_yara_hit_text",
            unsupported_reason="unsupported_yara_hit_text",
        )
        if reason == "" and text != "":
            return str.strip(text), ""
        if reason == "" and text == "" and isinstance(value, (str, bytes, bytearray, memoryview)):
            return "", "blank_yara_hit_text"
        for attr in _YARA_TEXT_ATTRS:
            attr_value = _plain_yara_attr(value, attr)
            if attr_value is _YARA_MISSING_VALUE:
                continue
            text, reason = _detached_yara_text(attr_value)
            if reason == "" and text != "":
                return text, ""
    except RECOVERABLE_RUNTIME_ERRORS:
        return YARA_HIT_TEXT_UNAVAILABLE, "unreadable_yara_hit_text"
    return YARA_HIT_TEXT_UNAVAILABLE, "unsupported_yara_hit_text"


def _yara_text(value: object) -> str:
    text, reason = _detached_yara_text(value)
    return "" if reason != "" or text == "" else text


def _first_yara_identity(*values: object) -> tuple[object, str]:
    last_reason = "missing_yara_hit_text"
    for value in values:
        if value is _YARA_MISSING_VALUE:
            continue
        text, reason = _detached_yara_text(value)
        if reason == "" and text != "":
            return value, ""
        if value is not None:
            last_reason = reason if reason != "" else "blank_yara_hit_text"
    return _YARA_MISSING_VALUE, last_reason


def _normalize_yara_rule_name_with_reason(rule: object) -> tuple[str, str]:
    if type(rule) is YaraHit:
        return rule.rule_identity.rule_name, ""
    if type(rule) is YaraRuleIdentity:
        return rule.rule_name, ""
    if type(rule) is YaraScanResult:
        return "", "yara_scan_result_not_single_rule"
    try:
        mapping_items = no_hook_mapping_items(rule)
        if mapping_items is not None:
            mapping = {key: value for key, value in mapping_items if type(key) is str}
            raw, reason = _first_yara_identity(
                dict.get(mapping, "rule"), dict.get(mapping, "name"), dict.get(mapping, "id")
            )
        else:
            raw, reason = _first_yara_identity(
                _plain_yara_attr(rule, "rule"), _plain_yara_attr(rule, "name"), rule
            )
        if reason != "":
            return "", reason
        name = _yara_text(raw)
        if not name:
            return "", "blank_yara_hit_text"
        name = re.sub(r"[^A-Za-z0-9_.:+/-]+", "_", name).strip("_")
        return (name[:160], "") if name else ("", "blank_yara_hit_text")
    except RECOVERABLE_RUNTIME_ERRORS:
        return "", "unreadable_yara_hit_text"


def normalize_yara_rule_name(rule: object) -> str:
    name, _reason = _normalize_yara_rule_name_with_reason(rule)
    return name


def _yara_hit_sequence(yara_hits: object) -> tuple[object, ...]:
    if type(yara_hits) is YaraScanResult:
        return tuple(yara_hits.hits)
    if yara_hits is None:
        return ()
    if isinstance(yara_hits, str) or type(yara_hits) in (bytes, bytearray, memoryview):
        return (yara_hits,)
    if type(yara_hits) in (tuple, list, set, frozenset):
        return tuple(yara_hits)
    if type(yara_hits) is dict:
        result = canonical_yara_scan_result(yara_hits)
        if result.unavailable_reason == "yara_scan_result_invalid":
            return (_YARA_SEQUENCE_FAILURE,)
        return tuple(result.hits)
    return (_YARA_SEQUENCE_FAILURE,)


def normalize_yara_hits(yara_hits: object) -> list[str]:
    hits: list[str] = []
    for hit in _yara_hit_sequence(yara_hits):
        if hit is _YARA_SEQUENCE_FAILURE:
            hits.append(YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE)
            continue
        name, reason = _normalize_yara_rule_name_with_reason(hit)
        if name:
            hits.append(name)
        elif hit is not None and reason not in ("blank_yara_hit_text", "missing_yara_hit_text"):
            hits.append(YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE)
    return sorted(set(hits))


def yara_expected_behavior(rule_name: object) -> str:
    name = normalize_yara_rule_name(rule_name)
    if not name:
        return "rule_match_unavailable"
    low = name.lower()
    if any(k in low for k in ("mimikatz", "steal", "credential", "lsass", "token", "browser")):
        return "credential_access"
    if any(k in low for k in ("ransom", "locker", "encrypt", "wiper", "shadow")):
        return "destructive_or_ransomware"
    if any(k in low for k in ("loader", "dropper", "packed", "packer", "payload", "inject")):
        return "loader_dropper_or_injection"
    if any(k in low for k in ("backdoor", "rat", "c2", "beacon", "trojan", "malware")):
        return "c2_or_backdoor"
    return "rule_match_context"


__all__ = (
    "ANALYTICAL_EVIDENCE_SCHEMA_VERSION",
    "YARA_CALIBRATION_VERSION",
    "YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE",
    "YARA_HIT_SCHEMA_VERSION",
    "YARA_HIT_TEXT_UNAVAILABLE",
    "YARA_RULE_IDENTITY_SCHEMA_VERSION",
    "YARA_SCAN_RESULT_SCHEMA_VERSION",
    "YaraHit",
    "YaraRuleIdentity",
    "YaraScanResult",
    "canonical_yara_hit_sequence",
    "canonical_yara_hits",
    "canonical_yara_scan_result",
    "merge_yara_scan_results",
    "normalize_yara_hits",
    "normalize_yara_rule_name",
    "unavailable_yara_scan_result",
    "yara_expected_behavior",
    "yara_hit_records",
    "yara_scan_result_record",
)
