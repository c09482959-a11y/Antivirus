"""Canonical projection-only YARA findings summary contracts and renderers.

This module consumes only final immutable scheduler-published YARA evidence. It
never loads rules, scans artifacts, reevaluates detections, or upgrades YARA
matches into malware probability or ATT&CK confirmation.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
import io
import json
import re
from typing import Mapping

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_sequence_items,
)
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.contracts.yara_hits import (
    YaraScanResult,
    unavailable_yara_scan_result,
)

YARA_SCAN_SUMMARY_ROW_SCHEMA_VERSION = "yara_scan_summary_row_v1"
YARA_FINDING_SUMMARY_ROW_SCHEMA_VERSION = "yara_finding_summary_row_v1"
YARA_FINDINGS_SUMMARY_SCHEMA_VERSION = "yara_findings_summary_v1"

_YARA_EXECUTED_STATUSES = frozenset({"complete", "complete_no_match", "partial", "truncated"})
_MITRE_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_MITRE_REFERENCE_KEYS = frozenset({
    "attack_id", "mitre_id", "technique_id", "technique_ids",
    "subtechnique_id", "subtechnique_ids",
})
_MAX_REFERENCE_ITEMS = 256
_MAX_RECORDS = 200_000
_MAX_TEXT = 4096


def _mapping_value(mapping: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for candidate, value in items:
        if type(candidate) is str and str.__eq__(candidate, key):
            return value
    return default


def _nonnegative_int(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool or value < 0:
        raise TypeError(reason)
    return value


def _optional_nonnegative_int(value: object, reason: str) -> int | None:
    if value is None:
        return None
    return _nonnegative_int(value, reason)


def _sorted_text_tuple(
    value: object,
    reason: str,
    *,
    maximum_items: int = _MAX_REFERENCE_ITEMS,
    maximum_text: int = _MAX_TEXT,
) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > maximum_items:
        raise TypeError(reason)
    normalized = tuple(
        exact_bounded_text(item, reason, maximum=maximum_text)
        for item in value
    )
    if normalized != tuple(sorted(set(normalized))):
        raise ValueError(reason)
    return normalized


def _record_key(value: object) -> str:
    return exact_bounded_text(value, "yara_summary_record_key_invalid", maximum=_MAX_TEXT)


def _reference_text(value: object) -> str:
    if type(value) is not str:
        return ""
    text = str.strip(str.__str__(value))
    return text[:_MAX_TEXT]


def _record_text_references(record: object, key: str) -> tuple[str, ...]:
    values = no_hook_sequence_items(_mapping_value(record, key, ()))
    references: set[str] = set()
    for value in values[:_MAX_REFERENCE_ITEMS]:
        text = _reference_text(value)
        if text:
            references.add(text)
            continue
        items = no_hook_mapping_items(value)
        if items is None:
            continue
        mapping = {candidate: item for candidate, item in items if type(candidate) is str}
        for identity_key in ("chain_id", "tag_id", "id", "name"):
            identity = _reference_text(dict.get(mapping, identity_key))
            if identity:
                references.add(identity)
                break
    return tuple(sorted(references))


def _collect_mitre_references(
    value: object,
    output: set[str],
    *,
    depth: int = 0,
) -> None:
    if depth > 8 or len(output) >= _MAX_REFERENCE_ITEMS:
        return
    items = no_hook_mapping_items(value)
    if items is not None:
        for key, item in items[:_MAX_REFERENCE_ITEMS]:
            key_text = str.__str__(key) if type(key) is str else ""
            if key_text in _MITRE_REFERENCE_KEYS:
                for candidate in no_hook_sequence_items(item)[:_MAX_REFERENCE_ITEMS]:
                    text = _reference_text(candidate)
                    if _MITRE_ID.fullmatch(text) is not None:
                        output.add(text)
            _collect_mitre_references(item, output, depth=depth + 1)
        return
    if type(value) in (tuple, list):
        for item in value[:_MAX_REFERENCE_ITEMS]:
            _collect_mitre_references(item, output, depth=depth + 1)


def _record_mitre_references(record: object) -> tuple[str, ...]:
    output: set[str] = set()
    for key in ("attack_intelligence", "mitre", "mitre_evidence"):
        _collect_mitre_references(_mapping_value(record, key), output)
    return tuple(sorted(output))


def _canonical_scan_result(value: object, record_key: str) -> tuple[YaraScanResult, bool]:
    if value is None:
        missing_digest = canonical_json_sha256({"record_key": record_key})[:24]
        return unavailable_yara_scan_result(
            "yara_evidence_not_published:" + missing_digest,
            status="unavailable",
        ), False
    if type(value) is YaraScanResult:
        return value, True
    materialized = no_hook_materialize(
        value,
        max_depth=20,
        max_items=4096,
        reason_prefix="yara_summary_source",
    )
    if type(materialized) is not dict:
        raise RuntimeError("yara_summary_source_invalid:" + record_key)
    try:
        return YaraScanResult.from_record(materialized), True
    except (TypeError, ValueError) as exc:
        raise RuntimeError("yara_summary_source_invalid:" + record_key) from exc


@dataclass(frozen=True, slots=True)
class YaraScanSummaryRow:
    record_keys: tuple[str, ...]
    source_evidence_present: bool
    status: str
    scan_pass_id: str
    physical_target_identity: str
    package_kind: str
    rule_source_digest: str
    compiled_cache_digest: str
    rule_catalog_digest: str
    source_schema_version: str
    total_match_count: int
    retained_match_count: int
    duplicate_match_count: int
    truncated_match_count: int
    archive_member_count: int
    scanned_member_count: int
    failed_member_count: int
    failure_reasons: tuple[str, ...]
    unavailable_reason: str
    retained_hit_identities: tuple[str, ...]
    schema_version: str = YARA_SCAN_SUMMARY_ROW_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not YaraScanSummaryRow:
            raise TypeError("yara_scan_summary_owner_invalid")
        if self.schema_version != YARA_SCAN_SUMMARY_ROW_SCHEMA_VERSION:
            raise ValueError("yara_scan_summary_schema_invalid")
        keys = _sorted_text_tuple(
            self.record_keys,
            "yara_scan_summary_record_keys_invalid",
            maximum_items=_MAX_REFERENCE_ITEMS,
        )
        if not keys:
            raise ValueError("yara_scan_summary_record_keys_invalid")
        if type(self.source_evidence_present) is not bool:
            raise TypeError("yara_scan_summary_source_state_invalid")
        for field_name, value, maximum, blank in (
            ("status", self.status, 32, False),
            ("scan_pass_id", self.scan_pass_id, 128, False),
            ("physical_target_identity", self.physical_target_identity, _MAX_TEXT, True),
            ("package_kind", self.package_kind, 32, False),
            ("rule_source_digest", self.rule_source_digest, 64, True),
            ("compiled_cache_digest", self.compiled_cache_digest, 64, True),
            ("rule_catalog_digest", self.rule_catalog_digest, 64, True),
            ("source_schema_version", self.source_schema_version, 128, False),
            ("unavailable_reason", self.unavailable_reason, 512, True),
        ):
            exact_bounded_text(
                value,
                "yara_scan_summary_" + field_name + "_invalid",
                maximum=maximum,
                allow_blank=blank,
            )
        for value in (
            self.total_match_count,
            self.retained_match_count,
            self.duplicate_match_count,
            self.truncated_match_count,
            self.archive_member_count,
            self.scanned_member_count,
            self.failed_member_count,
        ):
            _nonnegative_int(value, "yara_scan_summary_count_invalid")
        reasons = _sorted_text_tuple(
            self.failure_reasons,
            "yara_scan_summary_failure_reasons_invalid",
            maximum_items=64,
            maximum_text=256,
        )
        roots = _sorted_text_tuple(
            self.retained_hit_identities,
            "yara_scan_summary_hit_identities_invalid",
            maximum_items=256,
            maximum_text=256,
        )
        if len(roots) != self.retained_match_count:
            raise ValueError("yara_scan_summary_retained_count_mismatch")
        object.__setattr__(self, "record_keys", keys)
        object.__setattr__(self, "failure_reasons", reasons)
        object.__setattr__(self, "retained_hit_identities", roots)

    @classmethod
    def from_result(
        cls,
        result: YaraScanResult,
        *,
        record_keys: tuple[str, ...],
        source_evidence_present: bool,
    ) -> "YaraScanSummaryRow":
        if type(result) is not YaraScanResult:
            raise TypeError("yara_scan_summary_result_invalid")
        return cls(
            record_keys=record_keys,
            source_evidence_present=source_evidence_present,
            status=result.status,
            scan_pass_id=result.scan_pass_id,
            physical_target_identity=result.physical_target_identity,
            package_kind=result.package_kind,
            rule_source_digest=result.rule_source_digest,
            compiled_cache_digest=result.compiled_cache_digest,
            rule_catalog_digest=result.rule_catalog_digest,
            source_schema_version=result.schema_version,
            total_match_count=result.total_match_count,
            retained_match_count=result.retained_match_count,
            duplicate_match_count=result.duplicate_match_count,
            truncated_match_count=result.truncated_match_count,
            archive_member_count=result.archive_member_count,
            scanned_member_count=result.scanned_member_count,
            failed_member_count=result.failed_member_count,
            failure_reasons=result.failure_reasons,
            unavailable_reason=result.unavailable_reason,
            retained_hit_identities=tuple(sorted(
                hit.root_observation_id + ":" + hit.rule_identity.digest
                for hit in result.hits
            )),
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
            "package_kind": self.package_kind,
            "physical_target_identity": self.physical_target_identity,
            "record_keys": self.record_keys,
            "retained_hit_identities": self.retained_hit_identities,
            "retained_match_count": self.retained_match_count,
            "rule_catalog_digest": self.rule_catalog_digest,
            "rule_source_digest": self.rule_source_digest,
            "scan_pass_id": self.scan_pass_id,
            "scanned_member_count": self.scanned_member_count,
            "schema_version": self.schema_version,
            "source_schema_version": self.source_schema_version,
            "source_evidence_present": self.source_evidence_present,
            "status": self.status,
            "total_match_count": self.total_match_count,
            "truncated_match_count": self.truncated_match_count,
            "unavailable_reason": self.unavailable_reason,
        }


@dataclass(frozen=True, slots=True)
class YaraFindingSummaryRow:
    record_keys: tuple[str, ...]
    physical_target_identity: str
    scan_pass_id: str
    scan_status: str
    package_kind: str
    rule_source_digest: str
    compiled_cache_digest: str
    rule_catalog_digest: str
    source_member: str
    compiler_namespace: str
    rule_name: str
    metadata_id: str
    logic_hash: str
    semantic_metadata_digest: str
    rule_tags: tuple[str, ...]
    scan_result_schema_version: str
    rule_identity_schema_version: str
    hit_schema_version: str
    root_observation_id: str
    artifact_identity: str
    integrity_status: str
    source_trust: str
    hit_unavailable_reason: str
    verified: bool
    rule_mapping_eligible: bool
    release_id: int
    release_tag: str
    compile_policy_version: str
    source_location_type: str
    source_locator: str
    archive_member: str
    byte_offset: int | None
    byte_length: int | None
    event_id: str
    total_match_count: int
    retained_match_count: int
    duplicate_match_count: int
    truncated_match_count: int
    scan_failure_reasons: tuple[str, ...]
    scan_unavailable_reason: str
    downstream_tag_references: tuple[str, ...]
    downstream_chain_references: tuple[str, ...]
    downstream_mitre_references: tuple[str, ...]
    downstream_reference_scope: str = "record_level_unlinked"
    downstream_reference_unavailable_reason: str = "root_linkage_not_published"
    evidence_authority: str = "physical_rule_match"
    eligible_for_probability: bool = False
    eligible_for_attack_confirmation: bool = False
    schema_version: str = YARA_FINDING_SUMMARY_ROW_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not YaraFindingSummaryRow:
            raise TypeError("yara_finding_summary_owner_invalid")
        if self.schema_version != YARA_FINDING_SUMMARY_ROW_SCHEMA_VERSION:
            raise ValueError("yara_finding_summary_schema_invalid")
        keys = _sorted_text_tuple(
            self.record_keys,
            "yara_finding_summary_record_keys_invalid",
            maximum_items=_MAX_REFERENCE_ITEMS,
        )
        if not keys:
            raise ValueError("yara_finding_summary_record_keys_invalid")
        text_fields = (
            (self.physical_target_identity, "physical_target_identity", _MAX_TEXT, False),
            (self.scan_pass_id, "scan_pass_id", 128, False),
            (self.scan_status, "scan_status", 32, False),
            (self.package_kind, "package_kind", 32, False),
            (self.rule_source_digest, "rule_source_digest", 64, True),
            (self.compiled_cache_digest, "compiled_cache_digest", 64, True),
            (self.rule_catalog_digest, "rule_catalog_digest", 64, True),
            (self.source_member, "source_member", _MAX_TEXT, True),
            (self.compiler_namespace, "compiler_namespace", 160, True),
            (self.rule_name, "rule_name", 160, False),
            (self.metadata_id, "metadata_id", 160, True),
            (self.logic_hash, "logic_hash", 64, True),
            (self.semantic_metadata_digest, "semantic_metadata_digest", 64, True),
            (self.scan_result_schema_version, "scan_result_schema_version", 128, False),
            (self.rule_identity_schema_version, "rule_identity_schema_version", 128, False),
            (self.hit_schema_version, "hit_schema_version", 128, False),
            (self.root_observation_id, "root_observation_id", 128, False),
            (self.artifact_identity, "artifact_identity", _MAX_TEXT, False),
            (self.integrity_status, "integrity_status", 32, False),
            (self.source_trust, "source_trust", 32, False),
            (self.hit_unavailable_reason, "hit_unavailable_reason", 512, True),
            (self.release_tag, "release_tag", 128, True),
            (self.compile_policy_version, "compile_policy_version", 128, False),
            (self.source_location_type, "source_location_type", 64, False),
            (self.source_locator, "source_locator", _MAX_TEXT, True),
            (self.archive_member, "archive_member", _MAX_TEXT, True),
            (self.event_id, "event_id", 512, True),
            (self.scan_unavailable_reason, "scan_unavailable_reason", 512, True),
            (self.downstream_reference_scope, "downstream_reference_scope", 64, False),
            (self.downstream_reference_unavailable_reason, "downstream_reference_unavailable_reason", 256, True),
            (self.evidence_authority, "evidence_authority", 64, False),
        )
        for value, field_name, maximum, blank in text_fields:
            exact_bounded_text(
                value,
                "yara_finding_summary_" + field_name + "_invalid",
                maximum=maximum,
                allow_blank=blank,
            )
        if type(self.release_id) is not int or type(self.release_id) is bool or self.release_id < 0:
            raise TypeError("yara_finding_summary_release_id_invalid")
        for value in (
            self.total_match_count,
            self.retained_match_count,
            self.duplicate_match_count,
            self.truncated_match_count,
        ):
            _nonnegative_int(value, "yara_finding_summary_count_invalid")
        _optional_nonnegative_int(self.byte_offset, "yara_finding_summary_byte_offset_invalid")
        _optional_nonnegative_int(self.byte_length, "yara_finding_summary_byte_length_invalid")
        if (
            type(self.verified) is not bool
            or type(self.rule_mapping_eligible) is not bool
            or type(self.eligible_for_probability) is not bool
            or type(self.eligible_for_attack_confirmation) is not bool
        ):
            raise TypeError("yara_finding_summary_authority_state_invalid")
        if self.eligible_for_probability or self.eligible_for_attack_confirmation:
            raise ValueError("yara_finding_summary_unearned_authority")
        object.__setattr__(self, "record_keys", keys)
        object.__setattr__(self, "rule_tags", _sorted_text_tuple(
            self.rule_tags,
            "yara_finding_summary_rule_tags_invalid",
            maximum_items=32,
            maximum_text=128,
        ))
        object.__setattr__(self, "scan_failure_reasons", _sorted_text_tuple(
            self.scan_failure_reasons,
            "yara_finding_summary_failure_reasons_invalid",
            maximum_items=64,
            maximum_text=256,
        ))
        object.__setattr__(self, "downstream_tag_references", _sorted_text_tuple(
            self.downstream_tag_references,
            "yara_finding_summary_tag_references_invalid",
        ))
        object.__setattr__(self, "downstream_chain_references", _sorted_text_tuple(
            self.downstream_chain_references,
            "yara_finding_summary_chain_references_invalid",
        ))
        object.__setattr__(self, "downstream_mitre_references", _sorted_text_tuple(
            self.downstream_mitre_references,
            "yara_finding_summary_mitre_references_invalid",
            maximum_text=32,
        ))

    @property
    def rule_identity_digest(self) -> str:
        return canonical_json_sha256({
            "compiled_cache_digest": self.compiled_cache_digest,
            "compiler_namespace": self.compiler_namespace,
            "logic_hash": self.logic_hash,
            "metadata_id": self.metadata_id,
            "package_kind": self.package_kind,
            "rule_catalog_digest": self.rule_catalog_digest,
            "rule_name": self.rule_name,
            "rule_source_digest": self.rule_source_digest,
            "rule_tags": self.rule_tags,
            "schema_version": self.rule_identity_schema_version,
            "semantic_metadata_digest": self.semantic_metadata_digest,
            "source_member": self.source_member,
        })

    @property
    def semantic_digest(self) -> str:
        return canonical_json_sha256(self.to_record())

    def to_record(self) -> dict[str, object]:
        return {
            "archive_member": self.archive_member,
            "artifact_identity": self.artifact_identity,
            "byte_length": self.byte_length,
            "byte_offset": self.byte_offset,
            "compile_policy_version": self.compile_policy_version,
            "compiled_cache_digest": self.compiled_cache_digest,
            "compiler_namespace": self.compiler_namespace,
            "downstream_chain_references": self.downstream_chain_references,
            "downstream_mitre_references": self.downstream_mitre_references,
            "downstream_reference_scope": self.downstream_reference_scope,
            "downstream_reference_unavailable_reason": self.downstream_reference_unavailable_reason,
            "downstream_tag_references": self.downstream_tag_references,
            "duplicate_match_count": self.duplicate_match_count,
            "eligible_for_attack_confirmation": self.eligible_for_attack_confirmation,
            "eligible_for_probability": self.eligible_for_probability,
            "event_id": self.event_id,
            "evidence_authority": self.evidence_authority,
            "hit_schema_version": self.hit_schema_version,
            "hit_unavailable_reason": self.hit_unavailable_reason,
            "integrity_status": self.integrity_status,
            "logic_hash": self.logic_hash,
            "metadata_id": self.metadata_id,
            "package_kind": self.package_kind,
            "physical_target_identity": self.physical_target_identity,
            "record_keys": self.record_keys,
            "release_id": self.release_id,
            "release_tag": self.release_tag,
            "retained_match_count": self.retained_match_count,
            "root_observation_id": self.root_observation_id,
            "rule_catalog_digest": self.rule_catalog_digest,
            "rule_identity_digest": self.rule_identity_digest,
            "rule_name": self.rule_name,
            "rule_source_digest": self.rule_source_digest,
            "rule_mapping_eligible": self.rule_mapping_eligible,
            "rule_tags": self.rule_tags,
            "rule_identity_schema_version": self.rule_identity_schema_version,
            "scan_failure_reasons": self.scan_failure_reasons,
            "scan_pass_id": self.scan_pass_id,
            "scan_result_schema_version": self.scan_result_schema_version,
            "scan_status": self.scan_status,
            "scan_unavailable_reason": self.scan_unavailable_reason,
            "schema_version": self.schema_version,
            "semantic_metadata_digest": self.semantic_metadata_digest,
            "source_location_type": self.source_location_type,
            "source_locator": self.source_locator,
            "source_member": self.source_member,
            "source_trust": self.source_trust,
            "total_match_count": self.total_match_count,
            "truncated_match_count": self.truncated_match_count,
            "verified": self.verified,
        }


@dataclass(frozen=True, slots=True)
class YaraFindingsSummary:
    scan_id: str
    snapshot_semantic_digest: str
    source_record_count: int
    duplicate_alias_count: int
    scan_rows: tuple[YaraScanSummaryRow, ...]
    finding_rows: tuple[YaraFindingSummaryRow, ...]
    schema_version: str = YARA_FINDINGS_SUMMARY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not YaraFindingsSummary:
            raise TypeError("yara_findings_summary_owner_invalid")
        if self.schema_version != YARA_FINDINGS_SUMMARY_SCHEMA_VERSION:
            raise ValueError("yara_findings_summary_schema_invalid")
        exact_bounded_text(self.scan_id, "yara_findings_summary_scan_id_invalid", maximum=128)
        digest = exact_bounded_text(
            self.snapshot_semantic_digest,
            "yara_findings_summary_snapshot_digest_invalid",
            maximum=64,
        )
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("yara_findings_summary_snapshot_digest_invalid")
        _nonnegative_int(self.source_record_count, "yara_findings_summary_source_count_invalid")
        _nonnegative_int(self.duplicate_alias_count, "yara_findings_summary_alias_count_invalid")
        if type(self.scan_rows) is not tuple or any(type(item) is not YaraScanSummaryRow for item in self.scan_rows):
            raise TypeError("yara_findings_summary_scan_rows_invalid")
        if type(self.finding_rows) is not tuple or any(type(item) is not YaraFindingSummaryRow for item in self.finding_rows):
            raise TypeError("yara_findings_summary_finding_rows_invalid")
        retained = sum(row.retained_match_count for row in self.scan_rows)
        if retained != len(self.finding_rows):
            raise ValueError("yara_findings_summary_retained_reconciliation_failed")
        if self.source_record_count < len(self.scan_rows):
            raise ValueError("yara_findings_summary_source_reconciliation_failed")
        if self.duplicate_alias_count != self.source_record_count - len(self.scan_rows):
            raise ValueError("yara_findings_summary_alias_reconciliation_failed")

    @property
    def executed_scan_rows(self) -> tuple[YaraScanSummaryRow, ...]:
        return tuple(row for row in self.scan_rows if row.status in _YARA_EXECUTED_STATUSES)

    @property
    def one_scan_reconciled(self) -> bool:
        executed = self.executed_scan_rows
        targets = {row.physical_target_identity for row in executed}
        passes = {row.scan_pass_id for row in executed}
        return (
            all(row.physical_target_identity != "" for row in executed)
            and len(executed) == len(targets) == len(passes)
            and len(self.finding_rows) == sum(row.retained_match_count for row in self.scan_rows)
        )

    @property
    def semantic_digest(self) -> str:
        return canonical_json_sha256(self.core_record())

    def counts_record(self) -> dict[str, object]:
        status_counts: dict[str, int] = {}
        for row in self.scan_rows:
            status_counts[row.status] = status_counts.get(row.status, 0) + 1
        return {
            "duplicate_alias_count": self.duplicate_alias_count,
            "executed_scan_count": len(self.executed_scan_rows),
            "finding_count": len(self.finding_rows),
            "retained_match_count": sum(row.retained_match_count for row in self.scan_rows),
            "scan_row_count": len(self.scan_rows),
            "source_record_count": self.source_record_count,
            "status_counts": dict(sorted(status_counts.items())),
            "total_match_count": sum(row.total_match_count for row in self.scan_rows),
            "truncated_match_count": sum(row.truncated_match_count for row in self.scan_rows),
        }

    def reconciliation_record(self) -> dict[str, object]:
        executed = self.executed_scan_rows
        return {
            "executed_scan_count": len(executed),
            "one_scan_reconciled": self.one_scan_reconciled,
            "unique_physical_target_count": len({row.physical_target_identity for row in executed}),
            "unique_scan_pass_count": len({row.scan_pass_id for row in executed}),
        }

    def core_record(self) -> dict[str, object]:
        return {
            "counts": self.counts_record(),
            "evidence_authority": "physical_rule_match",
            "findings": tuple(row.to_record() for row in self.finding_rows),
            "one_scan_reconciliation": self.reconciliation_record(),
            "scan_id": self.scan_id,
            "scans": tuple(row.to_record() for row in self.scan_rows),
            "schema_version": self.schema_version,
            "snapshot_semantic_digest": self.snapshot_semantic_digest,
        }

    def to_record(self) -> dict[str, object]:
        record = self.core_record()
        record["summary_semantic_digest"] = self.semantic_digest
        return record


def build_yara_findings_summary(
    *,
    scan_id: object,
    snapshot_semantic_digest: object,
    local_results: object,
) -> YaraFindingsSummary:
    scan_id_text = exact_bounded_text(scan_id, "yara_findings_summary_scan_id_invalid", maximum=128)
    digest_text = exact_bounded_text(
        snapshot_semantic_digest,
        "yara_findings_summary_snapshot_digest_invalid",
        maximum=64,
    )
    items = no_hook_mapping_items(local_results)
    if items is None or len(items) > _MAX_RECORDS:
        raise TypeError("yara_findings_summary_local_results_invalid")
    ordered = sorted(
        items,
        key=lambda item: (
            _record_key(item[0]).replace("\\", "/").casefold(),
            _record_key(item[0]),
        ),
    )
    accumulated: dict[tuple[str, str], dict[str, object]] = {}
    scan_pass_targets: dict[str, str] = {}
    for raw_key, record in ordered:
        key = _record_key(raw_key)
        result, source_present = _canonical_scan_result(
            _mapping_value(record, "yara_evidence"),
            key,
        )
        tags = _record_text_references(record, "tags")
        chains = _record_text_references(record, "chains")
        mitre = _record_mitre_references(record)
        identity = (
            ("physical_target", result.physical_target_identity)
            if result.physical_target_identity != ""
            else ("record", key)
        )
        existing = accumulated.get(identity)
        if existing is None:
            accumulated[identity] = {
                "result": result,
                "source_present": source_present,
                "record_keys": {key},
                "tag_references": set(tags),
                "chain_references": set(chains),
                "mitre_references": set(mitre),
            }
        else:
            existing_result = existing["result"]
            if type(existing_result) is not YaraScanResult or existing_result.semantic_digest != result.semantic_digest:
                raise RuntimeError("yara_summary_physical_target_scan_conflict:" + result.physical_target_identity)
            existing["record_keys"].add(key)
            existing["tag_references"].update(tags)
            existing["chain_references"].update(chains)
            existing["mitre_references"].update(mitre)
            existing["source_present"] = bool(existing["source_present"] and source_present)
        if result.status in _YARA_EXECUTED_STATUSES:
            prior_target = scan_pass_targets.get(result.scan_pass_id)
            if prior_target is not None and prior_target != result.physical_target_identity:
                raise RuntimeError("yara_summary_scan_pass_target_conflict:" + result.scan_pass_id)
            scan_pass_targets[result.scan_pass_id] = result.physical_target_identity

    scan_rows: list[YaraScanSummaryRow] = []
    finding_rows: list[YaraFindingSummaryRow] = []
    for _identity, entry in sorted(
        accumulated.items(),
        key=lambda item: (
            item[0][0],
            item[0][1].replace("\\", "/").casefold(),
            item[0][1],
        ),
    ):
        result = entry["result"]
        if type(result) is not YaraScanResult:
            raise RuntimeError("yara_summary_internal_result_invalid")
        record_keys = tuple(sorted(entry["record_keys"]))
        scan_rows.append(YaraScanSummaryRow.from_result(
            result,
            record_keys=record_keys,
            source_evidence_present=entry["source_present"] is True,
        ))
        tag_references = tuple(sorted(entry["tag_references"]))
        chain_references = tuple(sorted(entry["chain_references"]))
        mitre_references = tuple(sorted(entry["mitre_references"]))
        for hit in result.hits:
            rule = hit.rule_identity
            location = hit.source_location
            finding_rows.append(YaraFindingSummaryRow(
                record_keys=record_keys,
                physical_target_identity=result.physical_target_identity,
                scan_pass_id=result.scan_pass_id,
                scan_status=result.status,
                package_kind=result.package_kind,
                rule_source_digest=result.rule_source_digest,
                compiled_cache_digest=result.compiled_cache_digest,
                rule_catalog_digest=result.rule_catalog_digest,
                source_member=rule.source_member,
                compiler_namespace=rule.compiler_namespace,
                rule_name=rule.rule_name,
                metadata_id=rule.metadata_id,
                logic_hash=rule.logic_hash,
                semantic_metadata_digest=rule.semantic_metadata_digest,
                rule_tags=rule.rule_tags,
                scan_result_schema_version=result.schema_version,
                rule_identity_schema_version=rule.schema_version,
                hit_schema_version=hit.schema_version,
                root_observation_id=hit.root_observation_id,
                artifact_identity=hit.artifact_identity,
                integrity_status=hit.integrity_status,
                source_trust=hit.source_trust,
                hit_unavailable_reason=hit.unavailable_reason,
                verified=hit.verified,
                rule_mapping_eligible=rule.mapping_eligible,
                release_id=hit.release_id,
                release_tag=hit.release_tag,
                compile_policy_version=hit.compile_policy_version,
                source_location_type=location.location_type,
                source_locator=location.locator,
                archive_member=location.archive_member,
                byte_offset=location.byte_offset,
                byte_length=location.byte_length,
                event_id=location.event_id,
                total_match_count=result.total_match_count,
                retained_match_count=result.retained_match_count,
                duplicate_match_count=result.duplicate_match_count,
                truncated_match_count=result.truncated_match_count,
                scan_failure_reasons=result.failure_reasons,
                scan_unavailable_reason=result.unavailable_reason,
                downstream_tag_references=tag_references,
                downstream_chain_references=chain_references,
                downstream_mitre_references=mitre_references,
            ))
    ordered_scans = tuple(sorted(
        scan_rows,
        key=lambda row: (
            row.physical_target_identity.replace("\\", "/").casefold(),
            row.scan_pass_id,
            row.record_keys,
        ),
    ))
    ordered_findings = tuple(sorted(
        finding_rows,
        key=lambda row: (
            row.artifact_identity.replace("\\", "/").casefold(),
            row.physical_target_identity.replace("\\", "/").casefold(),
            row.root_observation_id,
            row.rule_identity_digest,
            row.record_keys,
        ),
    ))
    summary = YaraFindingsSummary(
        scan_id=scan_id_text,
        snapshot_semantic_digest=digest_text,
        source_record_count=len(items),
        duplicate_alias_count=len(items) - len(ordered_scans),
        scan_rows=ordered_scans,
        finding_rows=ordered_findings,
    )
    if not summary.one_scan_reconciled:
        raise RuntimeError("yara_summary_one_scan_reconciliation_failed")
    return summary


def _json_sequence(value: tuple[str, ...]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _markdown_text(value: object) -> str:
    if value is None:
        return ""
    if type(value) is str:
        text = str.__str__(value)
    elif type(value) is int:
        text = int.__str__(value)
    elif type(value) is bool:
        text = "true" if value else "false"
    else:
        text = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return text.replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def yara_findings_json_bytes(summary: YaraFindingsSummary) -> bytes:
    if type(summary) is not YaraFindingsSummary:
        raise TypeError("yara_findings_summary_required")
    return (
        json.dumps(
            summary.to_record(),
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def yara_findings_markdown_bytes(summary: YaraFindingsSummary) -> bytes:
    if type(summary) is not YaraFindingsSummary:
        raise TypeError("yara_findings_summary_required")
    counts = summary.counts_record()
    reconciliation = summary.reconciliation_record()
    lines = [
        "# YARA Findings Summary",
        "",
        "- Scan ID: `" + _markdown_text(summary.scan_id) + "`",
        "- Snapshot semantic digest: `" + summary.snapshot_semantic_digest + "`",
        "- Summary semantic digest: `" + summary.semantic_digest + "`",
        "- Evidence authority: `physical_rule_match`",
        "- Executed scans: " + int.__str__(reconciliation["executed_scan_count"]),
        "- Findings: " + int.__str__(counts["finding_count"]),
        "- Total matches: " + int.__str__(counts["total_match_count"]),
        "- Retained matches: " + int.__str__(counts["retained_match_count"]),
        "- Truncated matches: " + int.__str__(counts["truncated_match_count"]),
        "- One-scan reconciliation: " + ("pass" if summary.one_scan_reconciled else "fail"),
        "",
        "## Scan reconciliation",
        "",
        "| Status | Scan pass | Physical target | Package | Total | Retained | Duplicate | Truncated | Records |",
        "|---|---|---|---|---:|---:|---:|---:|---|",
    ]
    for row in summary.scan_rows:
        lines.append("| " + " | ".join((
            _markdown_text(row.status),
            _markdown_text(row.scan_pass_id),
            _markdown_text(row.physical_target_identity),
            _markdown_text(row.package_kind),
            int.__str__(row.total_match_count),
            int.__str__(row.retained_match_count),
            int.__str__(row.duplicate_match_count),
            int.__str__(row.truncated_match_count),
            _markdown_text(row.record_keys),
        )) + " |")
    lines.extend(("", "## Findings", ""))
    if not summary.finding_rows:
        lines.append("No retained YARA findings were published. Disabled, unavailable, failed, and complete-no-match states remain explicit in the scan reconciliation table.")
    for index, row in enumerate(summary.finding_rows, 1):
        lines.extend((
            "### Finding " + int.__str__(index) + " — `" + _markdown_text(row.rule_name) + "`",
            "",
            "- Record keys: `" + _markdown_text(row.record_keys) + "`",
            "- Physical target identity: `" + _markdown_text(row.physical_target_identity) + "`",
            "- Scan pass ID: `" + _markdown_text(row.scan_pass_id) + "`",
            "- Package/source/catalog: `" + _markdown_text(row.package_kind) + "` / `" + row.rule_source_digest + "` / `" + row.rule_catalog_digest + "`",
            "- Compiled cache digest: `" + row.compiled_cache_digest + "`",
            "- Source member/namespace: `" + _markdown_text(row.source_member) + "` / `" + _markdown_text(row.compiler_namespace) + "`",
            "- Metadata ID: `" + _markdown_text(row.metadata_id) + "`",
            "- Logic/semantic metadata digests: `" + row.logic_hash + "` / `" + row.semantic_metadata_digest + "`",
            "- Root observation/artifact: `" + _markdown_text(row.root_observation_id) + "` / `" + _markdown_text(row.artifact_identity) + "`",
            "- Integrity/trust: `" + _markdown_text(row.integrity_status) + "` / `" + _markdown_text(row.source_trust) + "`",
            "- Release/policy: `" + int.__str__(row.release_id) + "` / `" + _markdown_text(row.release_tag) + "` / `" + _markdown_text(row.compile_policy_version) + "`",
            "- Source location: `" + _markdown_text({
                "archive_member": row.archive_member,
                "byte_length": row.byte_length,
                "byte_offset": row.byte_offset,
                "event_id": row.event_id,
                "location_type": row.source_location_type,
                "locator": row.source_locator,
            }) + "`",
            "- Match counts total/retained/duplicate/truncated: `" + "/".join((
                int.__str__(row.total_match_count),
                int.__str__(row.retained_match_count),
                int.__str__(row.duplicate_match_count),
                int.__str__(row.truncated_match_count),
            )) + "`",
            "- Downstream record-level Tag/Chain/MITRE references: `" + _markdown_text({
                "chains": row.downstream_chain_references,
                "mitre": row.downstream_mitre_references,
                "scope": row.downstream_reference_scope,
                "tags": row.downstream_tag_references,
                "unavailable_reason": row.downstream_reference_unavailable_reason,
            }) + "`",
            "- Authority: `physical_rule_match`; probability eligible: `false`; ATT&CK confirmation eligible: `false`",
            "",
        ))
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


_CSV_FIELDS = (
    "record_keys", "physical_target_identity", "scan_pass_id", "scan_status",
    "package_kind", "rule_source_digest", "compiled_cache_digest",
    "rule_catalog_digest", "source_member", "compiler_namespace", "rule_name",
    "metadata_id", "logic_hash", "semantic_metadata_digest", "rule_tags",
    "scan_result_schema_version", "rule_identity_schema_version", "hit_schema_version",
    "root_observation_id", "artifact_identity", "integrity_status", "source_trust",
    "hit_unavailable_reason", "verified", "rule_mapping_eligible",
    "release_id", "release_tag", "compile_policy_version", "source_location_type",
    "source_locator", "archive_member", "byte_offset", "byte_length", "event_id",
    "total_match_count", "retained_match_count", "duplicate_match_count",
    "truncated_match_count", "scan_failure_reasons", "scan_unavailable_reason",
    "downstream_tag_references", "downstream_chain_references",
    "downstream_mitre_references", "downstream_reference_scope",
    "downstream_reference_unavailable_reason", "evidence_authority",
    "eligible_for_probability", "eligible_for_attack_confirmation",
    "rule_identity_digest", "semantic_digest",
)


def yara_findings_csv_bytes(summary: YaraFindingsSummary) -> bytes:
    if type(summary) is not YaraFindingsSummary:
        raise TypeError("yara_findings_summary_required")
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=_CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in summary.finding_rows:
        record = row.to_record()
        writer.writerow({
            "record_keys": _json_sequence(row.record_keys),
            "physical_target_identity": row.physical_target_identity,
            "scan_pass_id": row.scan_pass_id,
            "scan_status": row.scan_status,
            "package_kind": row.package_kind,
            "rule_source_digest": row.rule_source_digest,
            "compiled_cache_digest": row.compiled_cache_digest,
            "rule_catalog_digest": row.rule_catalog_digest,
            "source_member": row.source_member,
            "compiler_namespace": row.compiler_namespace,
            "rule_name": row.rule_name,
            "metadata_id": row.metadata_id,
            "logic_hash": row.logic_hash,
            "semantic_metadata_digest": row.semantic_metadata_digest,
            "rule_tags": _json_sequence(row.rule_tags),
            "scan_result_schema_version": row.scan_result_schema_version,
            "rule_identity_schema_version": row.rule_identity_schema_version,
            "hit_schema_version": row.hit_schema_version,
            "root_observation_id": row.root_observation_id,
            "artifact_identity": row.artifact_identity,
            "integrity_status": row.integrity_status,
            "source_trust": row.source_trust,
            "hit_unavailable_reason": row.hit_unavailable_reason,
            "verified": row.verified,
            "rule_mapping_eligible": row.rule_mapping_eligible,
            "release_id": row.release_id,
            "release_tag": row.release_tag,
            "compile_policy_version": row.compile_policy_version,
            "source_location_type": row.source_location_type,
            "source_locator": row.source_locator,
            "archive_member": row.archive_member,
            "byte_offset": "" if row.byte_offset is None else row.byte_offset,
            "byte_length": "" if row.byte_length is None else row.byte_length,
            "event_id": row.event_id,
            "total_match_count": row.total_match_count,
            "retained_match_count": row.retained_match_count,
            "duplicate_match_count": row.duplicate_match_count,
            "truncated_match_count": row.truncated_match_count,
            "scan_failure_reasons": _json_sequence(row.scan_failure_reasons),
            "scan_unavailable_reason": row.scan_unavailable_reason,
            "downstream_tag_references": _json_sequence(row.downstream_tag_references),
            "downstream_chain_references": _json_sequence(row.downstream_chain_references),
            "downstream_mitre_references": _json_sequence(row.downstream_mitre_references),
            "downstream_reference_scope": row.downstream_reference_scope,
            "downstream_reference_unavailable_reason": row.downstream_reference_unavailable_reason,
            "evidence_authority": row.evidence_authority,
            "eligible_for_probability": record["eligible_for_probability"],
            "eligible_for_attack_confirmation": record["eligible_for_attack_confirmation"],
            "rule_identity_digest": row.rule_identity_digest,
            "semantic_digest": row.semantic_digest,
        })
    return stream.getvalue().encode("utf-8")


def render_yara_findings_summary(
    summary: YaraFindingsSummary,
) -> tuple[tuple[str, bytes], ...]:
    if type(summary) is not YaraFindingsSummary:
        raise TypeError("yara_findings_summary_required")
    return (
        ("yara_findings_summary.json", yara_findings_json_bytes(summary)),
        ("yara_findings_summary.md", yara_findings_markdown_bytes(summary)),
        ("yara_findings_summary.csv", yara_findings_csv_bytes(summary)),
    )


__all__ = (
    "YARA_FINDING_SUMMARY_ROW_SCHEMA_VERSION",
    "YARA_FINDINGS_SUMMARY_SCHEMA_VERSION",
    "YARA_SCAN_SUMMARY_ROW_SCHEMA_VERSION",
    "YaraFindingSummaryRow",
    "YaraFindingsSummary",
    "YaraScanSummaryRow",
    "build_yara_findings_summary",
    "render_yara_findings_summary",
    "yara_findings_csv_bytes",
    "yara_findings_json_bytes",
    "yara_findings_markdown_bytes",
)
