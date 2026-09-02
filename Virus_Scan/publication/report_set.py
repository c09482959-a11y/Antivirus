"""Canonical immutable final scan-publication snapshot and report-set transaction."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PosixPath, WindowsPath
import re
import time

from Virus_Scan.runtime.api import (
    durable_activate_directory,
    durable_replace_regular_file,
    flush_directory,
    flush_existing_regular_file,
    flush_open_writable_file,
    path_contains_filesystem_alias,
)
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.numeric_boundaries import exact_bool
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_materialize,
)
from Virus_Scan.core.jsonio import atomic_json_save
from Virus_Scan.core.logging import emit_parent_scan_log_event, release_single_parent_log
from Virus_Scan.runtime.api import ScanLogOutputPlan, freeze_runtime_value
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult
from Virus_Scan.publication.yara_summary import (
    YaraFindingsSummary,
    build_yara_findings_summary,
    render_yara_findings_summary,
)
from Virus_Scan.publication.chain_summary import (
    ChainFindingsSummary,
    build_chain_findings_summary,
    render_chain_findings_summary,
)
from Virus_Scan.publication.mitre_summary import (
    MitreFindingsSummary,
    build_mitre_findings_summary,
    render_mitre_findings_summary,
)
from Virus_Scan.publication.cluster_summary import (
    ClusterFindingsSummary,
    build_cluster_findings_summary,
    render_cluster_findings_summary,
)
from Virus_Scan.publication.virustotal_summary import (
    VirusTotalFindingsSummary,
    build_virustotal_findings_summary,
    render_virustotal_publication,
)
from Virus_Scan.publication.malicious_summary import (
    MaliciousFindingsSummary,
    build_malicious_findings_summary,
    render_malicious_findings_summary,
)

SCAN_PUBLICATION_SNAPSHOT_SCHEMA_VERSION = "scan_publication_snapshot_v3"
REPORT_MANIFEST_SCHEMA_VERSION = "scan_report_manifest_v8"
LATEST_PUBLICATION_POINTER_SCHEMA_VERSION = "scan_log_latest_pointer_v7"
REPORT_SET_PUBLICATION_RESULT_SCHEMA_VERSION = "scan_report_set_publication_result_v7"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_PUBLICATION_ITEMS = 200_000
_MAX_PUBLICATION_DEPTH = 48
_PATH_TYPES = (Path, PosixPath, WindowsPath)


def _exact_text(value: object, reason: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value)
    if not allow_empty and text == "":
        raise ValueError(reason)
    return text



def _exact_nonnegative_float(value: object, reason: str) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise TypeError(reason)
    metric = float(value)
    if not math.isfinite(metric) or metric < 0.0:
        raise ValueError(reason)
    return metric


def _exact_hex_or_blank(value: object, reason: str) -> str:
    text = _exact_text(value, reason, allow_empty=True)
    if text != "" and _HEX64.fullmatch(text) is None:
        raise ValueError(reason)
    return text


def _freeze_publication(value: object) -> object:
    return freeze_runtime_value(
        value,
        _max_depth=_MAX_PUBLICATION_DEPTH,
        _max_items=_MAX_PUBLICATION_ITEMS,
    )


def _materialize_publication(value: object) -> object:
    return no_hook_materialize(
        value,
        max_depth=_MAX_PUBLICATION_DEPTH,
        max_items=_MAX_PUBLICATION_ITEMS,
        reason_prefix="publication",
    )


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        _materialize_publication(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _semantic_digest(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    if type(path) not in _PATH_TYPES or not path.is_file():
        raise RuntimeError("scan_report_file_missing")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mapping_get(mapping: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for candidate, value in items:
        if type(candidate) is str and str.__eq__(candidate, key):
            return value
    return default


def _session_generation_from_results(results: object) -> tuple[str, str]:
    values: set[str] = set()
    items = no_hook_mapping_items(results)
    if items is None:
        return "", "local_results_mapping_unavailable"
    for _path, record in items:
        direct = _mapping_get(record, "scan_session_generation_id", "")
        if type(direct) is str and _HEX64.fullmatch(direct) is not None:
            values.add(str.__str__(direct))
            continue
        scan_session = _mapping_get(record, "scan_session")
        session_nested = _mapping_get(scan_session, "generation_id", "")
        if type(session_nested) is str and _HEX64.fullmatch(session_nested) is not None:
            values.add(str.__str__(session_nested))
            continue
        cache_identity = _mapping_get(record, "cache_execution_identity")
        nested = _mapping_get(cache_identity, "session_generation_id", "")
        if type(nested) is str and _HEX64.fullmatch(nested) is not None:
            values.add(str.__str__(nested))
    if len(values) == 1:
        return next(iter(values)), ""
    if len(values) > 1:
        raise ValueError("scan_publication_session_generation_conflict")
    return "", "session_generation_not_published_by_scheduler_result"


@dataclass(frozen=True, slots=True)
class ScanPublicationSnapshot:
    """One immutable final context for report projection and activation."""

    output_plan: ScanLogOutputPlan
    local_results: Mapping[str, object]
    ledger_summary: Mapping[str, object]
    virustotal_result: VirusTotalReportingResult
    persistence_status: object
    max_score: float
    elapsed_sec: float
    scan_had_error: bool
    session_generation_id: str = ""
    session_generation_unavailable_reason: str = ""
    schema_version: str = SCAN_PUBLICATION_SNAPSHOT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ScanPublicationSnapshot:
            raise TypeError("scan_publication_snapshot_owner_invalid")
        if type(self.output_plan) is not ScanLogOutputPlan:
            raise TypeError("scan_publication_output_plan_invalid")
        if self.schema_version != SCAN_PUBLICATION_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("scan_publication_snapshot_schema_invalid")
        local_results = _freeze_publication(self.local_results)
        ledger_summary = _freeze_publication(self.ledger_summary)
        persistence_status = _freeze_publication(self.persistence_status)
        if no_hook_mapping_items(local_results) is None:
            raise TypeError("scan_publication_local_results_invalid")
        if no_hook_mapping_items(ledger_summary) is None:
            raise TypeError("scan_publication_ledger_summary_invalid")
        if type(self.virustotal_result) is not VirusTotalReportingResult:
            raise TypeError("scan_publication_virustotal_result_invalid")
        generation = _exact_hex_or_blank(
            self.session_generation_id,
            "scan_publication_session_generation_invalid",
        )
        unavailable = _exact_text(
            self.session_generation_unavailable_reason,
            "scan_publication_session_generation_reason_invalid",
            allow_empty=True,
        )
        if generation == "" and unavailable == "":
            raise ValueError("scan_publication_session_generation_state_incomplete")
        if generation != "" and unavailable != "":
            raise ValueError("scan_publication_session_generation_state_conflict")
        object.__setattr__(self, "local_results", local_results)
        object.__setattr__(self, "ledger_summary", ledger_summary)
        object.__setattr__(self, "persistence_status", persistence_status)
        object.__setattr__(self, "max_score", _exact_nonnegative_float(self.max_score, "scan_publication_max_score_invalid"))
        object.__setattr__(self, "elapsed_sec", _exact_nonnegative_float(self.elapsed_sec, "scan_publication_elapsed_invalid"))
        object.__setattr__(self, "scan_had_error", exact_bool(self.scan_had_error, "scan_publication_error_state_invalid"))
        object.__setattr__(self, "session_generation_id", generation)
        object.__setattr__(self, "session_generation_unavailable_reason", unavailable)

    @property
    def local_result_count(self) -> int:
        items = no_hook_mapping_items(self.local_results)
        return 0 if items is None else len(items)

    @property
    def local_results_digest(self) -> str:
        return _semantic_digest(self.local_results)

    @property
    def semantic_digest(self) -> str:
        return _semantic_digest({
            "ledger_summary": self.ledger_summary,
            "local_result_count": self.local_result_count,
            "local_results_digest": self.local_results_digest,
            "max_score": self.max_score,
            "persistence_status": self.persistence_status,
            "scan_had_error": self.scan_had_error,
            "schema_version": self.schema_version,
            "session_generation_id": self.session_generation_id,
            "session_generation_unavailable_reason": self.session_generation_unavailable_reason,
            "virustotal_result": self.virustotal_result.to_record(),
        })

    def to_record(self) -> dict[str, object]:
        return {
            "elapsed_sec": self.elapsed_sec,
            "ledger_summary": _materialize_publication(self.ledger_summary),
            "local_result_count": self.local_result_count,
            "local_results_digest": self.local_results_digest,
            "max_score": self.max_score,
            "output_plan": self.output_plan.to_record(),
            "persistence_status": _materialize_publication(self.persistence_status),
            "scan_had_error": self.scan_had_error,
            "schema_version": self.schema_version,
            "semantic_digest": self.semantic_digest,
            "session_generation_id": self.session_generation_id,
            "session_generation_unavailable_reason": self.session_generation_unavailable_reason,
            "virustotal_result": self.virustotal_result.to_record(),
        }


@dataclass(frozen=True, slots=True)
class ReportManifest:
    scan_id: str
    snapshot_semantic_digest: str
    files: tuple[Mapping[str, object], ...]
    local_result_count: int
    malicious_summary_semantic_digest: str
    malicious_finding_count: int
    malicious_local_malicious_count: int
    malicious_local_suspicious_count: int
    malicious_external_or_context_only_count: int
    malicious_disagreement_count: int
    malicious_duplicate_alias_count: int
    virustotal_status: str
    virustotal_config_digest: str
    virustotal_summary_semantic_digest: str
    virustotal_finding_count: int
    virustotal_selected_count: int
    virustotal_submitted_count: int
    virustotal_skipped_count: int
    virustotal_disagreement_count: int
    persistence_ok: bool
    session_generation_id: str
    session_generation_unavailable_reason: str
    chain_summary_semantic_digest: str
    chain_decision_count: int
    chain_evidence_record_count: int
    chain_unique_evidence_count: int
    chain_duplicate_alias_count: int
    mitre_summary_semantic_digest: str
    mitre_decision_count: int
    mitre_confirmed_count: int
    mitre_candidate_count: int
    mitre_rejected_count: int
    mitre_unavailable_count: int
    cluster_summary_semantic_digest: str
    cluster_candidate_count: int
    cluster_evidence_record_count: int
    cluster_unique_evidence_count: int
    cluster_duplicate_alias_count: int
    cluster_available_count: int
    cluster_unavailable_count: int
    yara_summary_semantic_digest: str
    yara_scan_count: int
    yara_finding_count: int
    yara_total_match_count: int
    yara_retained_match_count: int
    yara_truncated_match_count: int
    yara_one_scan_reconciled: bool
    manifest_self_digest: str
    schema_version: str = REPORT_MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ReportManifest:
            raise TypeError("report_manifest_owner_invalid")
        if self.schema_version != REPORT_MANIFEST_SCHEMA_VERSION:
            raise ValueError("report_manifest_schema_invalid")
        _exact_text(self.scan_id, "report_manifest_scan_id_invalid")
        _exact_hex_or_blank(self.snapshot_semantic_digest, "report_manifest_snapshot_digest_invalid")
        _exact_hex_or_blank(self.malicious_summary_semantic_digest, "report_manifest_malicious_summary_digest_invalid")
        _exact_hex_or_blank(self.chain_summary_semantic_digest, "report_manifest_chain_summary_digest_invalid")
        _exact_hex_or_blank(self.mitre_summary_semantic_digest, "report_manifest_mitre_summary_digest_invalid")
        _exact_hex_or_blank(self.cluster_summary_semantic_digest, "report_manifest_cluster_summary_digest_invalid")
        _exact_hex_or_blank(self.virustotal_config_digest, "report_manifest_virustotal_config_digest_invalid")
        _exact_hex_or_blank(self.virustotal_summary_semantic_digest, "report_manifest_virustotal_summary_digest_invalid")
        _exact_hex_or_blank(self.yara_summary_semantic_digest, "report_manifest_yara_summary_digest_invalid")
        _exact_hex_or_blank(self.manifest_self_digest, "report_manifest_self_digest_invalid")
        for value in (
            self.local_result_count,
            self.malicious_finding_count,
            self.malicious_local_malicious_count,
            self.malicious_local_suspicious_count,
            self.malicious_external_or_context_only_count,
            self.malicious_disagreement_count,
            self.malicious_duplicate_alias_count,
            self.chain_decision_count,
            self.chain_evidence_record_count,
            self.chain_unique_evidence_count,
            self.chain_duplicate_alias_count,
            self.mitre_decision_count,
            self.mitre_confirmed_count,
            self.mitre_candidate_count,
            self.mitre_rejected_count,
            self.mitre_unavailable_count,
            self.cluster_candidate_count,
            self.cluster_evidence_record_count,
            self.cluster_unique_evidence_count,
            self.cluster_duplicate_alias_count,
            self.cluster_available_count,
            self.cluster_unavailable_count,
            self.virustotal_finding_count,
            self.virustotal_selected_count,
            self.virustotal_submitted_count,
            self.virustotal_skipped_count,
            self.virustotal_disagreement_count,
            self.yara_scan_count,
            self.yara_finding_count,
            self.yara_total_match_count,
            self.yara_retained_match_count,
            self.yara_truncated_match_count,
        ):
            if type(value) is not int or type(value) is bool or value < 0:
                raise ValueError("report_manifest_count_invalid")
        if self.malicious_finding_count != (
            self.malicious_local_malicious_count
            + self.malicious_local_suspicious_count
            + self.malicious_external_or_context_only_count
        ):
            raise ValueError("report_manifest_malicious_section_reconciliation_failed")
        if self.malicious_disagreement_count > self.malicious_finding_count:
            raise ValueError("report_manifest_malicious_disagreement_reconciliation_failed")
        if self.yara_finding_count != self.yara_retained_match_count:
            raise ValueError("report_manifest_yara_retained_reconciliation_failed")
        if self.mitre_decision_count != (
            self.mitre_confirmed_count
            + self.mitre_candidate_count
            + self.mitre_rejected_count
            + self.mitre_unavailable_count
        ):
            raise ValueError("report_manifest_mitre_count_reconciliation_failed")
        if self.cluster_evidence_record_count != self.cluster_unique_evidence_count + self.cluster_duplicate_alias_count:
            raise ValueError("report_manifest_cluster_alias_reconciliation_failed")
        if self.cluster_unique_evidence_count != self.cluster_available_count + self.cluster_unavailable_count:
            raise ValueError("report_manifest_cluster_availability_reconciliation_failed")
        if self.virustotal_finding_count != self.virustotal_selected_count:
            raise ValueError("report_manifest_virustotal_selected_reconciliation_failed")
        if self.virustotal_submitted_count + self.virustotal_skipped_count > self.virustotal_selected_count:
            raise ValueError("report_manifest_virustotal_submission_reconciliation_failed")
        _exact_text(self.virustotal_status, "report_manifest_virustotal_status_invalid")
        exact_bool(self.persistence_ok, "report_manifest_persistence_state_invalid")
        exact_bool(self.yara_one_scan_reconciled, "report_manifest_yara_reconciliation_invalid")
        if not self.yara_one_scan_reconciled:
            raise ValueError("report_manifest_yara_reconciliation_failed")
        generation = _exact_hex_or_blank(self.session_generation_id, "report_manifest_session_generation_invalid")
        unavailable = _exact_text(
            self.session_generation_unavailable_reason,
            "report_manifest_session_generation_reason_invalid",
            allow_empty=True,
        )
        if generation == "" and unavailable == "":
            raise ValueError("report_manifest_session_generation_state_incomplete")
        if generation != "" and unavailable != "":
            raise ValueError("report_manifest_session_generation_state_conflict")
        if type(self.files) is not tuple or not self.files:
            raise ValueError("report_manifest_files_invalid")
        object.__setattr__(self, "files", tuple(_freeze_publication(item) for item in self.files))

    def core_record(self) -> dict[str, object]:
        return {
            "files": [_materialize_publication(item) for item in self.files],
            "chain_decision_count": self.chain_decision_count,
            "chain_duplicate_alias_count": self.chain_duplicate_alias_count,
            "chain_evidence_record_count": self.chain_evidence_record_count,
            "chain_summary_semantic_digest": self.chain_summary_semantic_digest,
            "chain_unique_evidence_count": self.chain_unique_evidence_count,
            "mitre_candidate_count": self.mitre_candidate_count,
            "mitre_confirmed_count": self.mitre_confirmed_count,
            "mitre_decision_count": self.mitre_decision_count,
            "mitre_rejected_count": self.mitre_rejected_count,
            "mitre_unavailable_count": self.mitre_unavailable_count,
            "mitre_summary_semantic_digest": self.mitre_summary_semantic_digest,
            "cluster_available_count": self.cluster_available_count,
            "cluster_candidate_count": self.cluster_candidate_count,
            "cluster_duplicate_alias_count": self.cluster_duplicate_alias_count,
            "cluster_evidence_record_count": self.cluster_evidence_record_count,
            "cluster_summary_semantic_digest": self.cluster_summary_semantic_digest,
            "cluster_unavailable_count": self.cluster_unavailable_count,
            "cluster_unique_evidence_count": self.cluster_unique_evidence_count,
            "local_result_count": self.local_result_count,
            "malicious_disagreement_count": self.malicious_disagreement_count,
            "malicious_duplicate_alias_count": self.malicious_duplicate_alias_count,
            "malicious_external_or_context_only_count": self.malicious_external_or_context_only_count,
            "malicious_finding_count": self.malicious_finding_count,
            "malicious_local_malicious_count": self.malicious_local_malicious_count,
            "malicious_local_suspicious_count": self.malicious_local_suspicious_count,
            "malicious_summary_semantic_digest": self.malicious_summary_semantic_digest,
            "persistence_ok": self.persistence_ok,
            "scan_id": self.scan_id,
            "schema_version": self.schema_version,
            "session_generation_id": self.session_generation_id,
            "session_generation_unavailable_reason": self.session_generation_unavailable_reason,
            "snapshot_semantic_digest": self.snapshot_semantic_digest,
            "virustotal_config_digest": self.virustotal_config_digest,
            "virustotal_disagreement_count": self.virustotal_disagreement_count,
            "virustotal_finding_count": self.virustotal_finding_count,
            "virustotal_selected_count": self.virustotal_selected_count,
            "virustotal_skipped_count": self.virustotal_skipped_count,
            "virustotal_status": self.virustotal_status,
            "virustotal_submitted_count": self.virustotal_submitted_count,
            "virustotal_summary_semantic_digest": self.virustotal_summary_semantic_digest,
            "yara_finding_count": self.yara_finding_count,
            "yara_one_scan_reconciled": self.yara_one_scan_reconciled,
            "yara_retained_match_count": self.yara_retained_match_count,
            "yara_scan_count": self.yara_scan_count,
            "yara_summary_semantic_digest": self.yara_summary_semantic_digest,
            "yara_total_match_count": self.yara_total_match_count,
            "yara_truncated_match_count": self.yara_truncated_match_count,
        }

    def to_record(self) -> dict[str, object]:
        record = self.core_record()
        record["manifest_self_digest"] = self.manifest_self_digest
        return record


@dataclass(frozen=True, slots=True)
class ReportSetPublicationResult:
    scan_id: str
    run_path: str
    latest_path: str
    manifest_path: str
    manifest_file_sha256: str
    manifest_self_digest: str
    snapshot_semantic_digest: str
    malicious_summary_semantic_digest: str
    malicious_finding_count: int
    malicious_disagreement_count: int
    chain_summary_semantic_digest: str
    chain_decision_count: int
    mitre_summary_semantic_digest: str
    mitre_decision_count: int
    cluster_summary_semantic_digest: str
    cluster_candidate_count: int
    virustotal_status: str
    virustotal_summary_semantic_digest: str
    virustotal_finding_count: int
    virustotal_disagreement_count: int
    yara_summary_semantic_digest: str
    yara_scan_count: int
    yara_finding_count: int
    yara_one_scan_reconciled: bool
    schema_version: str = REPORT_SET_PUBLICATION_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ReportSetPublicationResult:
            raise TypeError("report_set_publication_result_owner_invalid")
        if self.schema_version != REPORT_SET_PUBLICATION_RESULT_SCHEMA_VERSION:
            raise ValueError("report_set_publication_result_schema_invalid")
        _exact_text(self.scan_id, "report_set_scan_id_invalid")
        for field_name in ("run_path", "latest_path", "manifest_path"):
            _exact_text(object.__getattribute__(self, field_name), "report_set_path_invalid")
        _exact_hex_or_blank(self.manifest_file_sha256, "report_set_manifest_file_digest_invalid")
        _exact_hex_or_blank(self.manifest_self_digest, "report_set_manifest_self_digest_invalid")
        _exact_hex_or_blank(self.snapshot_semantic_digest, "report_set_snapshot_digest_invalid")
        _exact_hex_or_blank(self.malicious_summary_semantic_digest, "report_set_malicious_summary_digest_invalid")
        _exact_hex_or_blank(self.chain_summary_semantic_digest, "report_set_chain_summary_digest_invalid")
        _exact_hex_or_blank(self.mitre_summary_semantic_digest, "report_set_mitre_summary_digest_invalid")
        _exact_hex_or_blank(self.cluster_summary_semantic_digest, "report_set_cluster_summary_digest_invalid")
        _exact_text(self.virustotal_status, "report_set_virustotal_status_invalid")
        _exact_hex_or_blank(self.virustotal_summary_semantic_digest, "report_set_virustotal_summary_digest_invalid")
        _exact_hex_or_blank(self.yara_summary_semantic_digest, "report_set_yara_summary_digest_invalid")
        for value in (
            self.malicious_finding_count,
            self.malicious_disagreement_count,
            self.chain_decision_count,
            self.mitre_decision_count,
            self.cluster_candidate_count,
            self.virustotal_finding_count,
            self.virustotal_disagreement_count,
            self.yara_scan_count,
            self.yara_finding_count,
        ):
            if type(value) is not int or type(value) is bool or value < 0:
                raise ValueError("report_set_yara_count_invalid")
        exact_bool(self.yara_one_scan_reconciled, "report_set_yara_reconciliation_invalid")
        if not self.yara_one_scan_reconciled:
            raise ValueError("report_set_yara_reconciliation_failed")

    def to_record(self) -> dict[str, object]:
        return {
            "latest_path": self.latest_path,
            "manifest_file_sha256": self.manifest_file_sha256,
            "manifest_path": self.manifest_path,
            "manifest_self_digest": self.manifest_self_digest,
            "run_path": self.run_path,
            "scan_id": self.scan_id,
            "malicious_finding_count": self.malicious_finding_count,
            "malicious_disagreement_count": self.malicious_disagreement_count,
            "malicious_summary_semantic_digest": self.malicious_summary_semantic_digest,
            "chain_decision_count": self.chain_decision_count,
            "chain_summary_semantic_digest": self.chain_summary_semantic_digest,
            "mitre_decision_count": self.mitre_decision_count,
            "mitre_summary_semantic_digest": self.mitre_summary_semantic_digest,
            "cluster_candidate_count": self.cluster_candidate_count,
            "cluster_summary_semantic_digest": self.cluster_summary_semantic_digest,
            "virustotal_status": self.virustotal_status,
            "virustotal_summary_semantic_digest": self.virustotal_summary_semantic_digest,
            "virustotal_finding_count": self.virustotal_finding_count,
            "virustotal_disagreement_count": self.virustotal_disagreement_count,
            "schema_version": self.schema_version,
            "snapshot_semantic_digest": self.snapshot_semantic_digest,
            "yara_finding_count": self.yara_finding_count,
            "yara_one_scan_reconciled": self.yara_one_scan_reconciled,
            "yara_scan_count": self.yara_scan_count,
            "yara_summary_semantic_digest": self.yara_summary_semantic_digest,
        }

def build_scan_publication_snapshot(
    *,
    output_plan: ScanLogOutputPlan,
    local_results: object,
    ledger_summary: object,
    virustotal_result: VirusTotalReportingResult,
    persistence_status: object,
    max_score: object,
    elapsed_sec: object,
    scan_had_error: object,
    session_generation_id: object | None = None,
) -> ScanPublicationSnapshot:
    if type(output_plan) is not ScanLogOutputPlan:
        raise TypeError("scan_publication_output_plan_invalid")
    if session_generation_id is None:
        generation, reason = _session_generation_from_results(local_results)
    else:
        generation = _exact_hex_or_blank(session_generation_id, "scan_publication_session_generation_invalid")
        reason = "" if generation else "session_generation_explicitly_unavailable"
    return ScanPublicationSnapshot(
        output_plan=output_plan,
        local_results=local_results,
        ledger_summary=ledger_summary,
        virustotal_result=virustotal_result,
        persistence_status=persistence_status,
        max_score=max_score,
        elapsed_sec=elapsed_sec,
        scan_had_error=scan_had_error,
        session_generation_id=generation,
        session_generation_unavailable_reason=reason,
    )


def _remove_completed_recovery_artifacts(staging: Path) -> None:
    for name in (
        "scan_results.json.partial",
        "scan_results.json.partial.checkpoint.json",
    ):
        candidate = staging / name
        if not candidate.exists():
            continue
        if path_contains_filesystem_alias(candidate) or not candidate.is_file():
            raise RuntimeError("scan_report_recovery_artifact_invalid:" + name)
        candidate.unlink()
    flush_directory(staging)


def _manifest_files(plan: ScanLogOutputPlan) -> tuple[dict[str, object], ...]:
    staging = Path(plan.staging_path)
    _remove_completed_recovery_artifacts(staging)
    allowed_names = frozenset(name for name, _path in plan.report_paths)
    present: list[dict[str, object]] = []
    unknown = []
    for child in sorted(staging.iterdir(), key=lambda item: item.name):
        if path_contains_filesystem_alias(child) or not child.is_file():
            unknown.append(child.name)
            continue
        if child.name == "report_manifest.json":
            raise RuntimeError("report_manifest_preexisting")
        if child.name not in allowed_names:
            unknown.append(child.name)
            continue
        flush_existing_regular_file(child)
        present.append({
            "filename": child.name,
            "sha256": _file_sha256(child),
            "size": child.stat().st_size,
        })
    if unknown:
        raise RuntimeError("scan_report_staging_unknown_files:" + ",".join(unknown))
    required = frozenset({
        "scan_results.json",
        "malicious_findings_summary.json",
        "malicious_findings_summary.md",
        "malicious_findings_summary.csv",
        "yara_findings_summary.json",
        "yara_findings_summary.md",
        "yara_findings_summary.csv",
        "chain_findings_summary.json",
        "chain_findings_summary.md",
        "chain_findings_summary.csv",
        "mitre_findings_summary.json",
        "mitre_findings_summary.md",
        "mitre_findings_summary.csv",
        "cluster_findings_summary.json",
        "cluster_findings_summary.md",
        "cluster_findings_summary.csv",
        "virustotal_results.json",
        "virustotal_findings_summary.json",
        "virustotal_findings_summary.md",
        "virustotal_findings_summary.csv",
    })
    present_names = frozenset(row["filename"] for row in present)
    missing = tuple(sorted(required - present_names))
    if missing:
        raise RuntimeError("scan_report_required_files_missing:" + ",".join(missing))
    return tuple(present)


def _persistence_ok(status: object) -> bool:
    if status is None:
        return True
    if type(status) is bool:
        return status
    return _mapping_get(status, "ok") is True


def build_report_manifest(
    snapshot: ScanPublicationSnapshot,
    yara_summary: YaraFindingsSummary,
    chain_summary: ChainFindingsSummary,
    mitre_summary: MitreFindingsSummary,
    cluster_summary: ClusterFindingsSummary,
    virustotal_summary: VirusTotalFindingsSummary,
    malicious_summary: MaliciousFindingsSummary,
) -> ReportManifest:
    if type(snapshot) is not ScanPublicationSnapshot:
        raise TypeError("scan_publication_snapshot_required")
    if type(yara_summary) is not YaraFindingsSummary:
        raise TypeError("yara_findings_summary_required")
    if type(chain_summary) is not ChainFindingsSummary:
        raise TypeError("chain_findings_summary_required")
    if type(mitre_summary) is not MitreFindingsSummary:
        raise TypeError("mitre_findings_summary_required")
    if type(cluster_summary) is not ClusterFindingsSummary:
        raise TypeError("cluster_findings_summary_required")
    if type(virustotal_summary) is not VirusTotalFindingsSummary:
        raise TypeError("virustotal_findings_summary_required")
    if type(malicious_summary) is not MaliciousFindingsSummary:
        raise TypeError("malicious_findings_summary_required")
    if malicious_summary.scan_id != snapshot.output_plan.scan_id:
        raise ValueError("report_manifest_malicious_scan_id_mismatch")
    if malicious_summary.snapshot_semantic_digest != snapshot.semantic_digest:
        raise ValueError("report_manifest_malicious_snapshot_digest_mismatch")
    if chain_summary.scan_id != snapshot.output_plan.scan_id:
        raise ValueError("report_manifest_chain_scan_id_mismatch")
    if chain_summary.snapshot_semantic_digest != snapshot.semantic_digest:
        raise ValueError("report_manifest_chain_snapshot_digest_mismatch")
    if mitre_summary.scan_id != snapshot.output_plan.scan_id:
        raise ValueError("report_manifest_mitre_scan_id_mismatch")
    if mitre_summary.snapshot_semantic_digest != snapshot.semantic_digest:
        raise ValueError("report_manifest_mitre_snapshot_digest_mismatch")
    if cluster_summary.scan_id != snapshot.output_plan.scan_id:
        raise ValueError("report_manifest_cluster_scan_id_mismatch")
    if cluster_summary.snapshot_semantic_digest != snapshot.semantic_digest:
        raise ValueError("report_manifest_cluster_snapshot_digest_mismatch")
    if virustotal_summary.scan_id != snapshot.output_plan.scan_id:
        raise ValueError("report_manifest_virustotal_scan_id_mismatch")
    if virustotal_summary.snapshot_semantic_digest != snapshot.semantic_digest:
        raise ValueError("report_manifest_virustotal_snapshot_digest_mismatch")
    if yara_summary.scan_id != snapshot.output_plan.scan_id:
        raise ValueError("report_manifest_yara_scan_id_mismatch")
    if yara_summary.snapshot_semantic_digest != snapshot.semantic_digest:
        raise ValueError("report_manifest_yara_snapshot_digest_mismatch")
    counts = yara_summary.counts_record()
    chain_counts = chain_summary.counts_record()
    mitre_counts = mitre_summary.counts_record()
    cluster_counts = cluster_summary.counts_record()
    virustotal_counts = virustotal_summary.counts_record()
    malicious_counts = malicious_summary.counts_record()
    files = _manifest_files(snapshot.output_plan)
    core = {
        "files": files,
        "chain_decision_count": chain_counts["decision_count"],
        "chain_duplicate_alias_count": chain_counts["duplicate_alias_count"],
        "chain_evidence_record_count": chain_counts["evidence_record_count"],
        "chain_summary_semantic_digest": chain_summary.semantic_digest,
        "chain_unique_evidence_count": chain_counts["unique_evidence_count"],
        "mitre_candidate_count": mitre_counts["candidate_count"],
        "mitre_confirmed_count": mitre_counts["confirmed_count"],
        "mitre_decision_count": mitre_counts["decision_count"],
        "mitre_rejected_count": mitre_counts["rejected_count"],
        "mitre_unavailable_count": mitre_counts["unavailable_decision_count"],
        "mitre_summary_semantic_digest": mitre_summary.semantic_digest,
        "cluster_available_count": cluster_counts["available_cluster_count"],
        "cluster_candidate_count": cluster_counts["candidate_count"],
        "cluster_duplicate_alias_count": cluster_counts["duplicate_alias_count"],
        "cluster_evidence_record_count": cluster_counts["evidence_record_count"],
        "cluster_summary_semantic_digest": cluster_summary.semantic_digest,
        "cluster_unavailable_count": cluster_counts["unavailable_cluster_count"],
        "cluster_unique_evidence_count": cluster_counts["unique_evidence_count"],
        "local_result_count": snapshot.local_result_count,
        "malicious_summary_semantic_digest": malicious_summary.semantic_digest,
        "malicious_finding_count": malicious_counts["finding_count"],
        "malicious_local_malicious_count": malicious_counts["local_malicious_count"],
        "malicious_local_suspicious_count": malicious_counts["local_suspicious_count"],
        "malicious_external_or_context_only_count": malicious_counts["external_or_context_only_count"],
        "malicious_disagreement_count": malicious_counts["disagreement_count"],
        "malicious_duplicate_alias_count": malicious_counts["duplicate_alias_count"],
        "persistence_ok": _persistence_ok(snapshot.persistence_status),
        "scan_id": snapshot.output_plan.scan_id,
        "schema_version": REPORT_MANIFEST_SCHEMA_VERSION,
        "session_generation_id": snapshot.session_generation_id,
        "session_generation_unavailable_reason": snapshot.session_generation_unavailable_reason,
        "snapshot_semantic_digest": snapshot.semantic_digest,
        "virustotal_status": snapshot.virustotal_result.status,
        "virustotal_config_digest": snapshot.virustotal_result.config_digest,
        "virustotal_summary_semantic_digest": virustotal_summary.semantic_digest,
        "virustotal_finding_count": virustotal_counts["finding_count"],
        "virustotal_selected_count": virustotal_counts["selected_count"],
        "virustotal_submitted_count": virustotal_counts["submitted_count"],
        "virustotal_skipped_count": virustotal_counts["skipped_count"],
        "virustotal_disagreement_count": virustotal_counts["disagreement_count"],
        "yara_finding_count": counts["finding_count"],
        "yara_one_scan_reconciled": yara_summary.one_scan_reconciled,
        "yara_retained_match_count": counts["retained_match_count"],
        "yara_scan_count": counts["scan_row_count"],
        "yara_summary_semantic_digest": yara_summary.semantic_digest,
        "yara_total_match_count": counts["total_match_count"],
        "yara_truncated_match_count": counts["truncated_match_count"],
    }
    return ReportManifest(
        scan_id=snapshot.output_plan.scan_id,
        snapshot_semantic_digest=snapshot.semantic_digest,
        files=files,
        local_result_count=snapshot.local_result_count,
        malicious_summary_semantic_digest=malicious_summary.semantic_digest,
        malicious_finding_count=malicious_counts["finding_count"],
        malicious_local_malicious_count=malicious_counts["local_malicious_count"],
        malicious_local_suspicious_count=malicious_counts["local_suspicious_count"],
        malicious_external_or_context_only_count=malicious_counts["external_or_context_only_count"],
        malicious_disagreement_count=malicious_counts["disagreement_count"],
        malicious_duplicate_alias_count=malicious_counts["duplicate_alias_count"],
        virustotal_status=snapshot.virustotal_result.status,
        virustotal_config_digest=snapshot.virustotal_result.config_digest,
        virustotal_summary_semantic_digest=virustotal_summary.semantic_digest,
        virustotal_finding_count=virustotal_counts["finding_count"],
        virustotal_selected_count=virustotal_counts["selected_count"],
        virustotal_submitted_count=virustotal_counts["submitted_count"],
        virustotal_skipped_count=virustotal_counts["skipped_count"],
        virustotal_disagreement_count=virustotal_counts["disagreement_count"],
        persistence_ok=_persistence_ok(snapshot.persistence_status),
        session_generation_id=snapshot.session_generation_id,
        session_generation_unavailable_reason=snapshot.session_generation_unavailable_reason,
        chain_summary_semantic_digest=chain_summary.semantic_digest,
        chain_decision_count=chain_counts["decision_count"],
        chain_evidence_record_count=chain_counts["evidence_record_count"],
        chain_unique_evidence_count=chain_counts["unique_evidence_count"],
        chain_duplicate_alias_count=chain_counts["duplicate_alias_count"],
        mitre_summary_semantic_digest=mitre_summary.semantic_digest,
        mitre_decision_count=mitre_counts["decision_count"],
        mitre_confirmed_count=mitre_counts["confirmed_count"],
        mitre_candidate_count=mitre_counts["candidate_count"],
        mitre_rejected_count=mitre_counts["rejected_count"],
        mitre_unavailable_count=mitre_counts["unavailable_decision_count"],
        cluster_summary_semantic_digest=cluster_summary.semantic_digest,
        cluster_candidate_count=cluster_counts["candidate_count"],
        cluster_evidence_record_count=cluster_counts["evidence_record_count"],
        cluster_unique_evidence_count=cluster_counts["unique_evidence_count"],
        cluster_duplicate_alias_count=cluster_counts["duplicate_alias_count"],
        cluster_available_count=cluster_counts["available_cluster_count"],
        cluster_unavailable_count=cluster_counts["unavailable_cluster_count"],
        yara_summary_semantic_digest=yara_summary.semantic_digest,
        yara_scan_count=counts["scan_row_count"],
        yara_finding_count=counts["finding_count"],
        yara_total_match_count=counts["total_match_count"],
        yara_retained_match_count=counts["retained_match_count"],
        yara_truncated_match_count=counts["truncated_match_count"],
        yara_one_scan_reconciled=yara_summary.one_scan_reconciled,
        manifest_self_digest=_semantic_digest(core),
    )

def _verify_malicious_summary_record(
    run: Path,
    *,
    scan_id: object,
    snapshot_semantic_digest: object,
    summary_semantic_digest: object,
    finding_count: object,
    local_malicious_count: object,
    local_suspicious_count: object,
    external_or_context_only_count: object,
    disagreement_count: object,
    duplicate_alias_count: object,
    yara_summary_semantic_digest: object,
    chain_summary_semantic_digest: object,
    mitre_summary_semantic_digest: object,
    cluster_summary_semantic_digest: object,
    virustotal_summary_semantic_digest: object,
) -> None:
    try:
        record = json.loads((run / "malicious_findings_summary.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("malicious_findings_summary_invalid") from exc
    if type(record) is not dict:
        raise RuntimeError("malicious_findings_summary_invalid")
    published_digest = dict.get(record, "summary_semantic_digest")
    core = dict(record)
    core.pop("summary_semantic_digest", None)
    if type(published_digest) is not str or _semantic_digest(core) != published_digest:
        raise RuntimeError("malicious_findings_summary_digest_mismatch")
    counts = dict.get(record, "counts")
    source_digests = dict.get(record, "source_summary_digests")
    policy = dict.get(record, "projection_policy")
    rows = dict.get(record, "rows")
    if type(counts) is not dict or type(source_digests) is not dict or type(policy) is not dict or type(rows) is not list:
        raise RuntimeError("malicious_findings_summary_reconciliation_invalid")
    expected = {
        "scan_id": scan_id,
        "snapshot_semantic_digest": snapshot_semantic_digest,
        "summary_semantic_digest": summary_semantic_digest,
        "finding_count": finding_count,
        "local_malicious_count": local_malicious_count,
        "local_suspicious_count": local_suspicious_count,
        "external_or_context_only_count": external_or_context_only_count,
        "disagreement_count": disagreement_count,
        "duplicate_alias_count": duplicate_alias_count,
        "yara": yara_summary_semantic_digest,
        "chain": chain_summary_semantic_digest,
        "mitre": mitre_summary_semantic_digest,
        "cluster": cluster_summary_semantic_digest,
        "virustotal": virustotal_summary_semantic_digest,
    }
    actual = {
        "scan_id": dict.get(record, "scan_id"),
        "snapshot_semantic_digest": dict.get(record, "snapshot_semantic_digest"),
        "summary_semantic_digest": published_digest,
        "finding_count": dict.get(counts, "finding_count"),
        "local_malicious_count": dict.get(counts, "local_malicious_count"),
        "local_suspicious_count": dict.get(counts, "local_suspicious_count"),
        "external_or_context_only_count": dict.get(counts, "external_or_context_only_count"),
        "disagreement_count": dict.get(counts, "disagreement_count"),
        "duplicate_alias_count": dict.get(counts, "duplicate_alias_count"),
        "yara": dict.get(source_digests, "yara"),
        "chain": dict.get(source_digests, "chain"),
        "mitre": dict.get(source_digests, "mitre"),
        "cluster": dict.get(source_digests, "cluster"),
        "virustotal": dict.get(source_digests, "virustotal"),
    }
    if actual != expected:
        raise RuntimeError("malicious_findings_summary_manifest_mismatch")
    if (
        dict.get(policy, "cross_subsystem_index_only") is not True
        or dict.get(policy, "report_time_detection") is not False
        or dict.get(policy, "report_time_scoring") is not False
        or dict.get(policy, "combined_score") is not None
        or dict.get(policy, "unknown_is_negative") is not False
    ):
        raise RuntimeError("malicious_findings_summary_policy_mismatch")
    identities: set[tuple[str, str]] = set()
    for row in rows:
        if type(row) is not dict:
            raise RuntimeError("malicious_findings_summary_row_invalid")
        sha256 = dict.get(row, "content_sha256")
        member = dict.get(row, "member_identity")
        reasons = dict.get(row, "inclusion_reasons")
        unavailable = dict.get(row, "unavailable_reasons")
        roots = dict.get(row, "physical_evidence_root_ids")
        if (
            type(sha256) is not str or _HEX64.fullmatch(sha256) is None
            or type(member) is not str
            or type(reasons) is not list or not reasons
            or type(unavailable) is not list
            or type(roots) is not list
            or dict.get(row, "combined_score") is not None
        ):
            raise RuntimeError("malicious_findings_summary_row_invalid")
        identity = (sha256, member)
        if identity in identities:
            raise RuntimeError("malicious_findings_summary_duplicate_identity")
        identities.add(identity)
        if not roots and "physical_evidence_roots_not_published_for_combined_row" not in unavailable:
            raise RuntimeError("malicious_findings_summary_root_state_invalid")


def _verify_yara_summary_record(
    run: Path,
    *,
    scan_id: object,
    snapshot_semantic_digest: object,
    summary_semantic_digest: object,
    scan_count: object,
    finding_count: object,
    total_match_count: object,
    retained_match_count: object,
    truncated_match_count: object,
    one_scan_reconciled: object,
) -> None:
    try:
        record = json.loads((run / "yara_findings_summary.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("yara_findings_summary_invalid") from exc
    if type(record) is not dict:
        raise RuntimeError("yara_findings_summary_invalid")
    published_digest = dict.get(record, "summary_semantic_digest")
    core = dict(record)
    core.pop("summary_semantic_digest", None)
    if type(published_digest) is not str or _semantic_digest(core) != published_digest:
        raise RuntimeError("yara_findings_summary_digest_mismatch")
    counts = dict.get(record, "counts")
    reconciliation = dict.get(record, "one_scan_reconciliation")
    if type(counts) is not dict or type(reconciliation) is not dict:
        raise RuntimeError("yara_findings_summary_reconciliation_invalid")
    expected = {
        "scan_id": scan_id,
        "snapshot_semantic_digest": snapshot_semantic_digest,
        "summary_semantic_digest": summary_semantic_digest,
        "scan_row_count": scan_count,
        "finding_count": finding_count,
        "total_match_count": total_match_count,
        "retained_match_count": retained_match_count,
        "truncated_match_count": truncated_match_count,
        "one_scan_reconciled": one_scan_reconciled,
    }
    actual = {
        "scan_id": dict.get(record, "scan_id"),
        "snapshot_semantic_digest": dict.get(record, "snapshot_semantic_digest"),
        "summary_semantic_digest": published_digest,
        "scan_row_count": dict.get(counts, "scan_row_count"),
        "finding_count": dict.get(counts, "finding_count"),
        "total_match_count": dict.get(counts, "total_match_count"),
        "retained_match_count": dict.get(counts, "retained_match_count"),
        "truncated_match_count": dict.get(counts, "truncated_match_count"),
        "one_scan_reconciled": dict.get(reconciliation, "one_scan_reconciled"),
    }
    if actual != expected:
        raise RuntimeError("yara_findings_summary_manifest_mismatch")



def _verify_chain_summary_record(
    run: Path,
    *,
    scan_id: object,
    snapshot_semantic_digest: object,
    summary_semantic_digest: object,
    decision_count: object,
    evidence_record_count: object,
    unique_evidence_count: object,
    duplicate_alias_count: object,
) -> None:
    try:
        record = json.loads((run / "chain_findings_summary.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("chain_findings_summary_invalid") from exc
    if type(record) is not dict:
        raise RuntimeError("chain_findings_summary_invalid")
    published_digest = dict.get(record, "summary_semantic_digest")
    core = dict(record)
    core.pop("summary_semantic_digest", None)
    if type(published_digest) is not str or _semantic_digest(core) != published_digest:
        raise RuntimeError("chain_findings_summary_digest_mismatch")
    counts = dict.get(record, "counts")
    if type(counts) is not dict:
        raise RuntimeError("chain_findings_summary_reconciliation_invalid")
    expected = {
        "scan_id": scan_id,
        "snapshot_semantic_digest": snapshot_semantic_digest,
        "summary_semantic_digest": summary_semantic_digest,
        "decision_count": decision_count,
        "evidence_record_count": evidence_record_count,
        "unique_evidence_count": unique_evidence_count,
        "duplicate_alias_count": duplicate_alias_count,
    }
    actual = {
        "scan_id": dict.get(record, "scan_id"),
        "snapshot_semantic_digest": dict.get(record, "snapshot_semantic_digest"),
        "summary_semantic_digest": published_digest,
        "decision_count": dict.get(counts, "decision_count"),
        "evidence_record_count": dict.get(counts, "evidence_record_count"),
        "unique_evidence_count": dict.get(counts, "unique_evidence_count"),
        "duplicate_alias_count": dict.get(counts, "duplicate_alias_count"),
    }
    if actual != expected:
        raise RuntimeError("chain_findings_summary_manifest_mismatch")


def _verify_mitre_summary_record(
    run: Path,
    *,
    scan_id: object,
    snapshot_semantic_digest: object,
    summary_semantic_digest: object,
    decision_count: object,
    confirmed_count: object,
    candidate_count: object,
    rejected_count: object,
    unavailable_count: object,
) -> None:
    try:
        record = json.loads((run / "mitre_findings_summary.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("mitre_findings_summary_invalid") from exc
    if type(record) is not dict:
        raise RuntimeError("mitre_findings_summary_invalid")
    published_digest = dict.get(record, "summary_semantic_digest")
    core = dict(record)
    core.pop("summary_semantic_digest", None)
    if type(published_digest) is not str or _semantic_digest(core) != published_digest:
        raise RuntimeError("mitre_findings_summary_digest_mismatch")
    counts = dict.get(record, "counts")
    if type(counts) is not dict:
        raise RuntimeError("mitre_findings_summary_reconciliation_invalid")
    expected = {
        "scan_id": scan_id,
        "snapshot_semantic_digest": snapshot_semantic_digest,
        "summary_semantic_digest": summary_semantic_digest,
        "decision_count": decision_count,
        "confirmed_count": confirmed_count,
        "candidate_count": candidate_count,
        "rejected_count": rejected_count,
        "unavailable_decision_count": unavailable_count,
    }
    actual = {
        "scan_id": dict.get(record, "scan_id"),
        "snapshot_semantic_digest": dict.get(record, "snapshot_semantic_digest"),
        "summary_semantic_digest": published_digest,
        "decision_count": dict.get(counts, "decision_count"),
        "confirmed_count": dict.get(counts, "confirmed_count"),
        "candidate_count": dict.get(counts, "candidate_count"),
        "rejected_count": dict.get(counts, "rejected_count"),
        "unavailable_decision_count": dict.get(counts, "unavailable_decision_count"),
    }
    if actual != expected:
        raise RuntimeError("mitre_findings_summary_manifest_mismatch")


def _verify_cluster_summary_record(
    run: Path,
    *,
    scan_id: object,
    snapshot_semantic_digest: object,
    summary_semantic_digest: object,
    candidate_count: object,
    evidence_record_count: object,
    unique_evidence_count: object,
    duplicate_alias_count: object,
    available_count: object,
    unavailable_count: object,
) -> None:
    try:
        record = json.loads((run / "cluster_findings_summary.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("cluster_findings_summary_invalid") from exc
    if type(record) is not dict:
        raise RuntimeError("cluster_findings_summary_invalid")
    published_digest = dict.get(record, "summary_semantic_digest")
    core = dict(record)
    core.pop("summary_semantic_digest", None)
    if type(published_digest) is not str or _semantic_digest(core) != published_digest:
        raise RuntimeError("cluster_findings_summary_digest_mismatch")
    counts = dict.get(record, "counts")
    if type(counts) is not dict:
        raise RuntimeError("cluster_findings_summary_reconciliation_invalid")
    expected = {
        "scan_id": scan_id,
        "snapshot_semantic_digest": snapshot_semantic_digest,
        "summary_semantic_digest": summary_semantic_digest,
        "candidate_count": candidate_count,
        "evidence_record_count": evidence_record_count,
        "unique_evidence_count": unique_evidence_count,
        "duplicate_alias_count": duplicate_alias_count,
        "available_cluster_count": available_count,
        "unavailable_cluster_count": unavailable_count,
    }
    actual = {
        "scan_id": dict.get(record, "scan_id"),
        "snapshot_semantic_digest": dict.get(record, "snapshot_semantic_digest"),
        "summary_semantic_digest": published_digest,
        "candidate_count": dict.get(counts, "candidate_count"),
        "evidence_record_count": dict.get(counts, "evidence_record_count"),
        "unique_evidence_count": dict.get(counts, "unique_evidence_count"),
        "duplicate_alias_count": dict.get(counts, "duplicate_alias_count"),
        "available_cluster_count": dict.get(counts, "available_cluster_count"),
        "unavailable_cluster_count": dict.get(counts, "unavailable_cluster_count"),
    }
    if actual != expected:
        raise RuntimeError("cluster_findings_summary_manifest_mismatch")


def _verify_virustotal_summary_record(
    run: Path,
    *,
    scan_id: object,
    snapshot_semantic_digest: object,
    config_digest: object,
    status: object,
    summary_semantic_digest: object,
    finding_count: object,
    selected_count: object,
    submitted_count: object,
    skipped_count: object,
    disagreement_count: object,
) -> None:
    try:
        record = json.loads((run / "virustotal_findings_summary.json").read_text(encoding="utf-8"))
        raw = json.loads((run / "virustotal_results.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("virustotal_findings_summary_invalid") from exc
    if type(record) is not dict or type(raw) is not dict:
        raise RuntimeError("virustotal_findings_summary_invalid")
    published_digest = dict.get(record, "summary_semantic_digest")
    core = dict(record)
    core.pop("summary_semantic_digest", None)
    if type(published_digest) is not str or _semantic_digest(core) != published_digest:
        raise RuntimeError("virustotal_findings_summary_digest_mismatch")
    counts = dict.get(record, "counts")
    if type(counts) is not dict:
        raise RuntimeError("virustotal_findings_summary_reconciliation_invalid")
    expected = {
        "scan_id": scan_id,
        "snapshot_semantic_digest": snapshot_semantic_digest,
        "config_digest": config_digest,
        "status": status,
        "summary_semantic_digest": summary_semantic_digest,
        "finding_count": finding_count,
        "selected_count": selected_count,
        "submitted_count": submitted_count,
        "skipped_count": skipped_count,
        "disagreement_count": disagreement_count,
        "evidence_authority": "external_corroboration",
        "local_result_mutated": False,
    }
    actual = {
        "scan_id": dict.get(record, "scan_id"),
        "snapshot_semantic_digest": dict.get(record, "snapshot_semantic_digest"),
        "config_digest": dict.get(record, "config_digest"),
        "status": dict.get(record, "status"),
        "summary_semantic_digest": published_digest,
        "finding_count": dict.get(counts, "finding_count"),
        "selected_count": dict.get(counts, "selected_count"),
        "submitted_count": dict.get(counts, "submitted_count"),
        "skipped_count": dict.get(counts, "skipped_count"),
        "disagreement_count": dict.get(counts, "disagreement_count"),
        "evidence_authority": dict.get(record, "evidence_authority"),
        "local_result_mutated": dict.get(record, "local_result_mutated"),
    }
    if actual != expected:
        raise RuntimeError("virustotal_findings_summary_manifest_mismatch")
    raw_digest = dict.get(raw, "results_semantic_digest")
    raw_core = dict(raw)
    raw_core.pop("results_semantic_digest", None)
    if type(raw_digest) is not str or _semantic_digest(raw_core) != raw_digest:
        raise RuntimeError("virustotal_results_digest_mismatch")
    if (
        dict.get(raw, "scan_id") != scan_id
        or dict.get(raw, "snapshot_semantic_digest") != snapshot_semantic_digest
        or dict.get(raw, "config_digest") != config_digest
        or dict.get(raw, "status") != status
        or dict.get(raw, "evidence_authority") != "external_corroboration"
        or dict.get(raw, "local_result_mutated") is not False
    ):
        raise RuntimeError("virustotal_results_manifest_mismatch")


def verify_report_manifest(run_path: object) -> ReportManifest:
    if type(run_path) is not str and type(run_path) not in _PATH_TYPES:
        raise TypeError("report_manifest_run_path_invalid")
    run = Path(run_path).absolute()
    if path_contains_filesystem_alias(run):
        raise RuntimeError("report_manifest_run_path_invalid")
    manifest_path = run / "report_manifest.json"
    try:
        record = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("report_manifest_invalid") from exc
    if type(record) is not dict:
        raise RuntimeError("report_manifest_invalid")
    self_digest = dict.get(record, "manifest_self_digest")
    core = dict(record)
    core.pop("manifest_self_digest", None)
    if type(self_digest) is not str or _semantic_digest(core) != self_digest:
        raise RuntimeError("report_manifest_self_digest_mismatch")
    files_value = dict.get(record, "files")
    if type(files_value) is not list or not files_value:
        raise RuntimeError("report_manifest_files_invalid")
    file_rows: list[Mapping[str, object]] = []
    for row in files_value:
        if type(row) is not dict:
            raise RuntimeError("report_manifest_file_row_invalid")
        filename = dict.get(row, "filename")
        size = dict.get(row, "size")
        sha256 = dict.get(row, "sha256")
        if type(filename) is not str or Path(filename).name != filename:
            raise RuntimeError("report_manifest_filename_invalid")
        if type(size) is not int or type(size) is bool or size < 0:
            raise RuntimeError("report_manifest_file_size_invalid")
        if type(sha256) is not str or _HEX64.fullmatch(sha256) is None:
            raise RuntimeError("report_manifest_file_digest_invalid")
        target = run / filename
        if (
            path_contains_filesystem_alias(target)
            or not target.is_file()
            or target.stat().st_size != size
            or _file_sha256(target) != sha256
        ):
            raise RuntimeError("report_manifest_file_mismatch:" + filename)
        file_rows.append(MappingProxyType(dict(row)))
    manifest = ReportManifest(
        scan_id=dict.get(record, "scan_id"),
        snapshot_semantic_digest=dict.get(record, "snapshot_semantic_digest"),
        files=tuple(file_rows),
        local_result_count=dict.get(record, "local_result_count"),
        malicious_summary_semantic_digest=dict.get(record, "malicious_summary_semantic_digest"),
        malicious_finding_count=dict.get(record, "malicious_finding_count"),
        malicious_local_malicious_count=dict.get(record, "malicious_local_malicious_count"),
        malicious_local_suspicious_count=dict.get(record, "malicious_local_suspicious_count"),
        malicious_external_or_context_only_count=dict.get(record, "malicious_external_or_context_only_count"),
        malicious_disagreement_count=dict.get(record, "malicious_disagreement_count"),
        malicious_duplicate_alias_count=dict.get(record, "malicious_duplicate_alias_count"),
        virustotal_status=dict.get(record, "virustotal_status"),
        virustotal_config_digest=dict.get(record, "virustotal_config_digest"),
        virustotal_summary_semantic_digest=dict.get(record, "virustotal_summary_semantic_digest"),
        virustotal_finding_count=dict.get(record, "virustotal_finding_count"),
        virustotal_selected_count=dict.get(record, "virustotal_selected_count"),
        virustotal_submitted_count=dict.get(record, "virustotal_submitted_count"),
        virustotal_skipped_count=dict.get(record, "virustotal_skipped_count"),
        virustotal_disagreement_count=dict.get(record, "virustotal_disagreement_count"),
        persistence_ok=dict.get(record, "persistence_ok"),
        session_generation_id=dict.get(record, "session_generation_id"),
        session_generation_unavailable_reason=dict.get(record, "session_generation_unavailable_reason"),
        chain_summary_semantic_digest=dict.get(record, "chain_summary_semantic_digest"),
        chain_decision_count=dict.get(record, "chain_decision_count"),
        chain_evidence_record_count=dict.get(record, "chain_evidence_record_count"),
        chain_unique_evidence_count=dict.get(record, "chain_unique_evidence_count"),
        chain_duplicate_alias_count=dict.get(record, "chain_duplicate_alias_count"),
        mitre_summary_semantic_digest=dict.get(record, "mitre_summary_semantic_digest"),
        mitre_decision_count=dict.get(record, "mitre_decision_count"),
        mitre_confirmed_count=dict.get(record, "mitre_confirmed_count"),
        mitre_candidate_count=dict.get(record, "mitre_candidate_count"),
        mitre_rejected_count=dict.get(record, "mitre_rejected_count"),
        mitre_unavailable_count=dict.get(record, "mitre_unavailable_count"),
        cluster_summary_semantic_digest=dict.get(record, "cluster_summary_semantic_digest"),
        cluster_candidate_count=dict.get(record, "cluster_candidate_count"),
        cluster_evidence_record_count=dict.get(record, "cluster_evidence_record_count"),
        cluster_unique_evidence_count=dict.get(record, "cluster_unique_evidence_count"),
        cluster_duplicate_alias_count=dict.get(record, "cluster_duplicate_alias_count"),
        cluster_available_count=dict.get(record, "cluster_available_count"),
        cluster_unavailable_count=dict.get(record, "cluster_unavailable_count"),
        yara_summary_semantic_digest=dict.get(record, "yara_summary_semantic_digest"),
        yara_scan_count=dict.get(record, "yara_scan_count"),
        yara_finding_count=dict.get(record, "yara_finding_count"),
        yara_total_match_count=dict.get(record, "yara_total_match_count"),
        yara_retained_match_count=dict.get(record, "yara_retained_match_count"),
        yara_truncated_match_count=dict.get(record, "yara_truncated_match_count"),
        yara_one_scan_reconciled=dict.get(record, "yara_one_scan_reconciled"),
        manifest_self_digest=self_digest,
        schema_version=dict.get(record, "schema_version"),
    )
    if manifest.to_record() != record:
        raise RuntimeError("report_manifest_record_mismatch")
    _verify_malicious_summary_record(
        run,
        scan_id=manifest.scan_id,
        snapshot_semantic_digest=manifest.snapshot_semantic_digest,
        summary_semantic_digest=manifest.malicious_summary_semantic_digest,
        finding_count=manifest.malicious_finding_count,
        local_malicious_count=manifest.malicious_local_malicious_count,
        local_suspicious_count=manifest.malicious_local_suspicious_count,
        external_or_context_only_count=manifest.malicious_external_or_context_only_count,
        disagreement_count=manifest.malicious_disagreement_count,
        duplicate_alias_count=manifest.malicious_duplicate_alias_count,
        yara_summary_semantic_digest=manifest.yara_summary_semantic_digest,
        chain_summary_semantic_digest=manifest.chain_summary_semantic_digest,
        mitre_summary_semantic_digest=manifest.mitre_summary_semantic_digest,
        cluster_summary_semantic_digest=manifest.cluster_summary_semantic_digest,
        virustotal_summary_semantic_digest=manifest.virustotal_summary_semantic_digest,
    )
    _verify_chain_summary_record(
        run,
        scan_id=manifest.scan_id,
        snapshot_semantic_digest=manifest.snapshot_semantic_digest,
        summary_semantic_digest=manifest.chain_summary_semantic_digest,
        decision_count=manifest.chain_decision_count,
        evidence_record_count=manifest.chain_evidence_record_count,
        unique_evidence_count=manifest.chain_unique_evidence_count,
        duplicate_alias_count=manifest.chain_duplicate_alias_count,
    )
    _verify_mitre_summary_record(
        run,
        scan_id=manifest.scan_id,
        snapshot_semantic_digest=manifest.snapshot_semantic_digest,
        summary_semantic_digest=manifest.mitre_summary_semantic_digest,
        decision_count=manifest.mitre_decision_count,
        confirmed_count=manifest.mitre_confirmed_count,
        candidate_count=manifest.mitre_candidate_count,
        rejected_count=manifest.mitre_rejected_count,
        unavailable_count=manifest.mitre_unavailable_count,
    )
    _verify_cluster_summary_record(
        run,
        scan_id=manifest.scan_id,
        snapshot_semantic_digest=manifest.snapshot_semantic_digest,
        summary_semantic_digest=manifest.cluster_summary_semantic_digest,
        candidate_count=manifest.cluster_candidate_count,
        evidence_record_count=manifest.cluster_evidence_record_count,
        unique_evidence_count=manifest.cluster_unique_evidence_count,
        duplicate_alias_count=manifest.cluster_duplicate_alias_count,
        available_count=manifest.cluster_available_count,
        unavailable_count=manifest.cluster_unavailable_count,
    )
    _verify_virustotal_summary_record(
        run,
        scan_id=manifest.scan_id,
        snapshot_semantic_digest=manifest.snapshot_semantic_digest,
        config_digest=manifest.virustotal_config_digest,
        status=manifest.virustotal_status,
        summary_semantic_digest=manifest.virustotal_summary_semantic_digest,
        finding_count=manifest.virustotal_finding_count,
        selected_count=manifest.virustotal_selected_count,
        submitted_count=manifest.virustotal_submitted_count,
        skipped_count=manifest.virustotal_skipped_count,
        disagreement_count=manifest.virustotal_disagreement_count,
    )
    _verify_yara_summary_record(
        run,
        scan_id=manifest.scan_id,
        snapshot_semantic_digest=manifest.snapshot_semantic_digest,
        summary_semantic_digest=manifest.yara_summary_semantic_digest,
        scan_count=manifest.yara_scan_count,
        finding_count=manifest.yara_finding_count,
        total_match_count=manifest.yara_total_match_count,
        retained_match_count=manifest.yara_retained_match_count,
        truncated_match_count=manifest.yara_truncated_match_count,
        one_scan_reconciled=manifest.yara_one_scan_reconciled,
    )
    return manifest


def _restore_latest_pointer(latest: Path, previous: bytes | None, root: Path) -> None:
    if previous is None:
        latest.unlink(missing_ok=True)
        flush_directory(root)
        return
    restore = latest.with_name("." + latest.name + ".restore.tmp")
    with restore.open("wb") as stream:
        stream.write(previous)
        stream.flush()
        flush_open_writable_file(stream.fileno())
    durable_replace_regular_file(restore, latest)


def _publish_latest_pointer(latest: Path, record: dict[str, object], scan_id: str, root: Path) -> None:
    if path_contains_filesystem_alias(latest) or (
        latest.exists() and not latest.is_file()
    ):
        raise RuntimeError("scan_report_latest_path_invalid")
    previous = latest.read_bytes() if latest.exists() else None
    temporary = latest.with_name("." + latest.name + "." + scan_id + ".tmp")
    temporary.unlink(missing_ok=True)
    try:
        atomic_json_save(str(temporary), record, backups=0)
        try:
            staged = json.loads(temporary.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("scan_report_latest_staging_invalid") from exc
        if staged != record:
            raise RuntimeError("scan_report_latest_staging_mismatch")
        flush_existing_regular_file(temporary)
        durable_replace_regular_file(temporary, latest)
        try:
            published = json.loads(latest.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            _restore_latest_pointer(latest, previous, root)
            raise RuntimeError("scan_report_latest_invalid") from exc
        if published != record:
            _restore_latest_pointer(latest, previous, root)
            raise RuntimeError("scan_report_latest_verification_mismatch")
    finally:
        temporary.unlink(missing_ok=True)


def _persistence_ok_for_scanlog(snapshot: ScanPublicationSnapshot) -> bool:
    items = no_hook_mapping_items(snapshot.persistence_status)
    if items is None:
        return snapshot.persistence_status is True
    for key, value in items:
        if type(key) is str and str.__eq__(key, "ok"):
            return value is True
    return False


def _emit_final_scanlog_projection_events(
    snapshot: ScanPublicationSnapshot,
    yara_summary: YaraFindingsSummary,
    chain_summary: ChainFindingsSummary,
    mitre_summary: MitreFindingsSummary,
    cluster_summary: ClusterFindingsSummary,
    virustotal_summary: VirusTotalFindingsSummary,
    malicious_summary: MaliciousFindingsSummary,
    projected_report_count: int,
) -> None:
    yara_counts = yara_summary.counts_record()
    chain_counts = chain_summary.counts_record()
    mitre_counts = mitre_summary.counts_record()
    cluster_counts = cluster_summary.counts_record()
    vt_counts = virustotal_summary.counts_record()
    malicious_counts = malicious_summary.counts_record()
    common = {
        "scan_id": snapshot.output_plan.scan_id,
        "snapshot_semantic_digest": snapshot.semantic_digest,
    }
    emit_parent_scan_log_event("SCAN", {
        **common,
        "event": "final_publication_snapshot",
        "local_result_count": snapshot.local_result_count,
        "persistence_ok": _persistence_ok_for_scanlog(snapshot),
        "scan_had_error": snapshot.scan_had_error,
    }, mirror_console=False)
    emit_parent_scan_log_event("YARA", {
        **common,
        "event": "final_projection",
        "summary_semantic_digest": yara_summary.semantic_digest,
        "scan_count": yara_counts["scan_row_count"],
        "finding_count": yara_counts["finding_count"],
        "total_match_count": yara_counts["total_match_count"],
        "retained_match_count": yara_counts["retained_match_count"],
        "truncated_match_count": yara_counts["truncated_match_count"],
        "one_scan_reconciled": yara_summary.one_scan_reconciled,
        "evidence_authority": "physical_rule_match",
    }, mirror_console=False)
    emit_parent_scan_log_event("CHAIN", {
        **common,
        "event": "final_projection",
        "summary_semantic_digest": chain_summary.semantic_digest,
        "decision_count": chain_counts["decision_count"],
        "evidence_record_count": chain_counts["evidence_record_count"],
        "unique_evidence_count": chain_counts["unique_evidence_count"],
        "duplicate_alias_count": chain_counts["duplicate_alias_count"],
    }, mirror_console=False)
    emit_parent_scan_log_event("MITRE", {
        **common,
        "event": "final_projection",
        "summary_semantic_digest": mitre_summary.semantic_digest,
        "decision_count": mitre_counts["decision_count"],
        "confirmed_count": mitre_counts["confirmed_count"],
        "candidate_count": mitre_counts["candidate_count"],
        "rejected_count": mitre_counts["rejected_count"],
        "execution_observed": False,
    }, mirror_console=False)
    emit_parent_scan_log_event("CLUSTER", {
        **common,
        "event": "final_projection",
        "summary_semantic_digest": cluster_summary.semantic_digest,
        "candidate_count": cluster_counts["candidate_count"],
        "available_count": cluster_counts["available_cluster_count"],
        "unavailable_count": cluster_counts["unavailable_cluster_count"],
        "evidence_authority": "context_only",
        "eligible_for_confirmation": False,
        "eligible_for_probability": False,
    }, mirror_console=False)
    emit_parent_scan_log_event("VT", {
        **common,
        "event": "final_projection",
        "status": virustotal_summary.status,
        "summary_semantic_digest": virustotal_summary.semantic_digest,
        "finding_count": vt_counts["finding_count"],
        "disagreement_count": vt_counts["disagreement_count"],
        "evidence_authority": "external_corroboration",
        "local_result_mutated": False,
        "unknown_is_negative": False,
    }, mirror_console=False)
    emit_parent_scan_log_event("SUMMARY", {
        **common,
        "event": "combined_malicious_findings",
        "summary_semantic_digest": malicious_summary.semantic_digest,
        "finding_count": malicious_counts["finding_count"],
        "local_malicious_count": malicious_counts["local_malicious_count"],
        "local_suspicious_count": malicious_counts["local_suspicious_count"],
        "external_or_context_only_count": malicious_counts["external_or_context_only_count"],
        "disagreement_count": malicious_counts["disagreement_count"],
        "duplicate_alias_count": malicious_counts["duplicate_alias_count"],
        "combined_score": None,
        "unknown_is_negative": False,
    }, mirror_console=False)
    emit_parent_scan_log_event("REPORT_SET", {
        **common,
        "event": "publication_prepared",
        "completion_state": "prepared_not_activated",
        "projected_report_count": projected_report_count,
        "report_manifest_schema_version": REPORT_MANIFEST_SCHEMA_VERSION,
        "activation_record_owner": "latest.json",
    }, mirror_console=False)


def _write_projected_report(staging: Path, filename: str, payload: bytes) -> None:
    if type(filename) is not str or Path(filename).name != filename:
        raise TypeError("scan_report_projected_filename_invalid")
    if type(payload) is not bytes:
        raise TypeError("scan_report_projected_payload_invalid")
    target = staging / filename
    if target.exists() or path_contains_filesystem_alias(target):
        raise RuntimeError("scan_report_projected_file_preexisting:" + filename)
    with target.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        flush_open_writable_file(stream.fileno())


def publish_scan_report_set(snapshot: ScanPublicationSnapshot) -> ReportSetPublicationResult:
    """Project, log, verify, activate, and point at exactly one report generation."""
    if type(snapshot) is not ScanPublicationSnapshot:
        raise TypeError("scan_publication_snapshot_required")
    plan = snapshot.output_plan
    staging = Path(plan.staging_path).absolute()
    run = Path(plan.run_path).absolute()
    latest = Path(plan.latest_path).absolute()
    root = Path(plan.scan_log_root).absolute()
    if path_contains_filesystem_alias(staging) or not staging.is_dir():
        raise RuntimeError("scan_report_staging_missing")
    if any(
        path_contains_filesystem_alias(path)
        for path in (run.parent, latest.parent, root)
    ):
        raise RuntimeError("scan_report_path_alias_rejected")
    if run.exists():
        raise RuntimeError("scan_report_run_already_exists")
    run.parent.mkdir(parents=True, exist_ok=True)

    scanlog_path = plan.staging_report_path("scanlog").as_posix()
    try:
        yara_summary = build_yara_findings_summary(
            scan_id=plan.scan_id,
            snapshot_semantic_digest=snapshot.semantic_digest,
            local_results=snapshot.local_results,
        )
        chain_summary = build_chain_findings_summary(
            scan_id=plan.scan_id,
            snapshot_semantic_digest=snapshot.semantic_digest,
            local_results=snapshot.local_results,
        )
        mitre_summary = build_mitre_findings_summary(
            scan_id=plan.scan_id,
            snapshot_semantic_digest=snapshot.semantic_digest,
            local_results=snapshot.local_results,
        )
        cluster_summary = build_cluster_findings_summary(
            scan_id=plan.scan_id,
            snapshot_semantic_digest=snapshot.semantic_digest,
            local_results=snapshot.local_results,
        )
        virustotal_summary = build_virustotal_findings_summary(
            scan_id=plan.scan_id,
            snapshot_semantic_digest=snapshot.semantic_digest,
            local_results=snapshot.local_results,
            virustotal_result=snapshot.virustotal_result,
        )
        malicious_summary = build_malicious_findings_summary(
            scan_id=plan.scan_id,
            snapshot_semantic_digest=snapshot.semantic_digest,
            local_results=snapshot.local_results,
            yara_summary=yara_summary,
            chain_summary=chain_summary,
            mitre_summary=mitre_summary,
            cluster_summary=cluster_summary,
            virustotal_summary=virustotal_summary,
        )
        projected_reports = (
            render_yara_findings_summary(yara_summary)
            + render_chain_findings_summary(chain_summary)
            + render_mitre_findings_summary(mitre_summary)
            + render_cluster_findings_summary(cluster_summary)
            + render_virustotal_publication(virustotal_summary)
            + render_malicious_findings_summary(malicious_summary)
        )
        _emit_final_scanlog_projection_events(
            snapshot,
            yara_summary,
            chain_summary,
            mitre_summary,
            cluster_summary,
            virustotal_summary,
            malicious_summary,
            len(projected_reports),
        )
    finally:
        release_single_parent_log(scanlog_path)

    created_reports: list[str] = []
    manifest_path = staging / "report_manifest.json"
    manifest_created = False
    try:
        for filename, payload in projected_reports:
            _write_projected_report(staging, filename, payload)
            created_reports.append(filename)
        flush_directory(staging)
        manifest = build_report_manifest(
            snapshot, yara_summary, chain_summary, mitre_summary, cluster_summary,
            virustotal_summary, malicious_summary,
        )
        atomic_json_save(str(manifest_path), manifest.to_record(), backups=0)
        manifest_created = True
        flush_existing_regular_file(manifest_path)
        flush_directory(staging)
        durable_activate_directory(staging, run)
    except (OSError, RuntimeError, TypeError, ValueError):
        if staging.is_dir():
            if (
                manifest_created
                and manifest_path.is_file()
                and not path_contains_filesystem_alias(manifest_path)
            ):
                manifest_path.unlink()
            for filename in reversed(created_reports):
                target = staging / filename
                if target.is_file() and not path_contains_filesystem_alias(target):
                    target.unlink()
            flush_directory(staging)
        raise
    verified = verify_report_manifest(run)
    final_manifest_path = run / "report_manifest.json"
    manifest_file_sha256 = _file_sha256(final_manifest_path)
    latest_record = {
        "activated_at_ns": time.time_ns(),
        "completion_state": "complete",
        "manifest_file_sha256": manifest_file_sha256,
        "manifest_self_digest": verified.manifest_self_digest,
        "run_path": run.as_posix(),
        "scan_id": plan.scan_id,
        "schema_version": LATEST_PUBLICATION_POINTER_SCHEMA_VERSION,
        "snapshot_semantic_digest": snapshot.semantic_digest,
        "malicious_summary_semantic_digest": verified.malicious_summary_semantic_digest,
        "malicious_finding_count": verified.malicious_finding_count,
        "malicious_disagreement_count": verified.malicious_disagreement_count,
        "chain_decision_count": verified.chain_decision_count,
        "chain_summary_semantic_digest": verified.chain_summary_semantic_digest,
        "mitre_decision_count": verified.mitre_decision_count,
        "mitre_summary_semantic_digest": verified.mitre_summary_semantic_digest,
        "cluster_candidate_count": verified.cluster_candidate_count,
        "cluster_summary_semantic_digest": verified.cluster_summary_semantic_digest,
        "virustotal_status": verified.virustotal_status,
        "virustotal_finding_count": verified.virustotal_finding_count,
        "virustotal_disagreement_count": verified.virustotal_disagreement_count,
        "virustotal_summary_semantic_digest": verified.virustotal_summary_semantic_digest,
        "yara_finding_count": verified.yara_finding_count,
        "yara_one_scan_reconciled": verified.yara_one_scan_reconciled,
        "yara_scan_count": verified.yara_scan_count,
        "yara_summary_semantic_digest": verified.yara_summary_semantic_digest,
    }
    latest_record["session_generation_id"] = snapshot.session_generation_id
    latest_record["session_generation_unavailable_reason"] = snapshot.session_generation_unavailable_reason
    _publish_latest_pointer(latest, latest_record, plan.scan_id, root)
    return ReportSetPublicationResult(
        scan_id=plan.scan_id,
        run_path=run.as_posix(),
        latest_path=latest.as_posix(),
        manifest_path=final_manifest_path.as_posix(),
        manifest_file_sha256=manifest_file_sha256,
        manifest_self_digest=verified.manifest_self_digest,
        snapshot_semantic_digest=snapshot.semantic_digest,
        malicious_summary_semantic_digest=verified.malicious_summary_semantic_digest,
        malicious_finding_count=verified.malicious_finding_count,
        malicious_disagreement_count=verified.malicious_disagreement_count,
        chain_summary_semantic_digest=verified.chain_summary_semantic_digest,
        chain_decision_count=verified.chain_decision_count,
        mitre_summary_semantic_digest=verified.mitre_summary_semantic_digest,
        mitre_decision_count=verified.mitre_decision_count,
        cluster_summary_semantic_digest=verified.cluster_summary_semantic_digest,
        cluster_candidate_count=verified.cluster_candidate_count,
        virustotal_status=verified.virustotal_status,
        virustotal_summary_semantic_digest=verified.virustotal_summary_semantic_digest,
        virustotal_finding_count=verified.virustotal_finding_count,
        virustotal_disagreement_count=verified.virustotal_disagreement_count,
        yara_summary_semantic_digest=verified.yara_summary_semantic_digest,
        yara_scan_count=verified.yara_scan_count,
        yara_finding_count=verified.yara_finding_count,
        yara_one_scan_reconciled=verified.yara_one_scan_reconciled,
    )


__all__ = (
    "LATEST_PUBLICATION_POINTER_SCHEMA_VERSION",
    "REPORT_MANIFEST_SCHEMA_VERSION",
    "REPORT_SET_PUBLICATION_RESULT_SCHEMA_VERSION",
    "SCAN_PUBLICATION_SNAPSHOT_SCHEMA_VERSION",
    "ReportManifest",
    "ReportSetPublicationResult",
    "ScanPublicationSnapshot",
    "build_report_manifest",
    "build_scan_publication_snapshot",
    "publish_scan_report_set",
    "verify_report_manifest",
)
