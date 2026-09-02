"""Projection-only VirusTotal external-corroboration publication.

The projector consumes the immutable :class:`VirusTotalReportingResult` plus the
same final local-result mapping already frozen by ``ScanPublicationSnapshot``.
It does not submit files, poll VirusTotal, rescan artifacts, alter local verdicts,
or create local evidence authority.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
import io
import json
import math

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_materialize
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.publication.content_identity import exact_content_sha256, final_record_content_sha256
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult

VIRUSTOTAL_FINDING_SUMMARY_ROW_SCHEMA_VERSION = "virustotal_finding_summary_row_v1"
VIRUSTOTAL_FINDINGS_SUMMARY_SCHEMA_VERSION = "virustotal_findings_summary_v1"
VIRUSTOTAL_NORMALIZED_RESULTS_SCHEMA_VERSION = "virustotal_normalized_results_v1"
_MAX_TEXT = 4096
_MAX_ROWS = 200_000
_MAX_FULL_RESPONSE_ITEMS = 20_000


def _mapping_get(mapping: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for candidate, value in items:
        if type(candidate) is str and str.__eq__(candidate, key):
            return value
    return default


def _text(value: object, reason: str, *, allow_blank: bool = False, maximum: int = _MAX_TEXT) -> str:
    if value is None and allow_blank:
        return ""
    return exact_bounded_text(value, reason, maximum=maximum, allow_blank=allow_blank)


def _bool(value: object, reason: str, *, default: bool | None = None) -> bool:
    if value is None and default is not None:
        return default
    if type(value) is not bool:
        raise TypeError(reason)
    return value


def _count(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool or value < 0:
        raise TypeError(reason)
    return value


def _score(value: object, reason: str) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise TypeError(reason)
    number = float(value)
    if not math.isfinite(number) or number < 0.0:
        raise ValueError(reason)
    return number


def _local_record(local_results: object, artifact_path: str) -> object:
    items = no_hook_mapping_items(local_results)
    if items is None:
        raise TypeError("virustotal_summary_local_results_invalid")
    for key, record in items:
        if type(key) is str and str.__eq__(key, artifact_path):
            return record
    raise RuntimeError("virustotal_summary_local_result_missing:" + artifact_path)


def _local_verdict(record: object, fallback: str) -> str:
    for key in ("classification", "verdict", "class"):
        value = _mapping_get(record, key)
        if type(value) is str and value != "":
            return _text(value, "virustotal_summary_local_verdict_invalid", maximum=128)
    return fallback


def _engine_counts(summary: object) -> tuple[str, int, int, int, int, int, int, int]:
    if summary is None:
        return "unavailable", 0, 0, 0, 0, 0, 0, 0
    if no_hook_mapping_items(summary) is None:
        raise TypeError("virustotal_summary_engine_summary_invalid")
    status = _text(_mapping_get(summary, "status", "unknown"), "virustotal_summary_analysis_status_invalid", maximum=128)
    values = tuple(
        _count(_mapping_get(summary, key, 0), "virustotal_summary_engine_count_invalid")
        for key in ("malicious", "suspicious", "harmless", "undetected", "timeout", "failure", "type_unsupported")
    )
    return (status, *values)


def _disagreement(local_verdict: str, analysis_status: str, completed: bool, malicious: int, suspicious: int) -> str:
    if not completed or analysis_status != "completed":
        return "unknown_external_incomplete"
    local_positive = local_verdict.strip().lower() in {"malicious", "high", "high_confidence"}
    external_positive = malicious > 0 or suspicious > 0
    if local_positive and external_positive:
        return "agreement_positive"
    if not local_positive and not external_positive:
        return "agreement_negative"
    if local_positive:
        return "local_positive_external_nonpositive"
    return "local_nonpositive_external_positive"


@dataclass(frozen=True, slots=True)
class VirusTotalFindingSummaryRow:
    artifact_path: str
    content_sha256: str
    local_verdict: str
    local_score: float
    selection_reason: str
    submitted: bool
    skipped: bool
    reporting_status: str
    analysis_status: str
    analysis_id: str
    permalink: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    timeout: int
    failure: int
    type_unsupported: int
    engine_total: int
    analysis_complete: bool
    error: str
    disagreement_state: str
    evidence_authority: str = "external_corroboration"
    local_result_mutated: bool = False
    full_response: object | None = None
    schema_version: str = VIRUSTOTAL_FINDING_SUMMARY_ROW_SCHEMA_VERSION

    @property
    def semantic_digest(self) -> str:
        return canonical_json_sha256(self.summary_record())

    def summary_record(self) -> dict[str, object]:
        return {
            "analysis_complete": self.analysis_complete,
            "analysis_id": self.analysis_id,
            "analysis_status": self.analysis_status,
            "artifact_path": self.artifact_path,
            "content_sha256": self.content_sha256,
            "disagreement_state": self.disagreement_state,
            "engine_counts": {
                "failure": self.failure,
                "harmless": self.harmless,
                "malicious": self.malicious,
                "suspicious": self.suspicious,
                "timeout": self.timeout,
                "type_unsupported": self.type_unsupported,
                "undetected": self.undetected,
            },
            "engine_total": self.engine_total,
            "error": self.error,
            "evidence_authority": self.evidence_authority,
            "local_result_mutated": self.local_result_mutated,
            "local_score": self.local_score,
            "local_verdict": self.local_verdict,
            "permalink": self.permalink,
            "reporting_status": self.reporting_status,
            "schema_version": self.schema_version,
            "selection_reason": self.selection_reason,
            "skipped": self.skipped,
            "submitted": self.submitted,
        }

    def raw_record(self, *, include_full_response: bool) -> dict[str, object]:
        record = self.summary_record()
        record["row_semantic_digest"] = self.semantic_digest
        if include_full_response and self.full_response is not None:
            record["full_response"] = no_hook_materialize(
                self.full_response,
                max_depth=24,
                max_items=_MAX_FULL_RESPONSE_ITEMS,
                reason_prefix="virustotal_full_response",
            )
        return record


@dataclass(frozen=True, slots=True)
class VirusTotalFindingsSummary:
    scan_id: str
    snapshot_semantic_digest: str
    status: str
    config_digest: str
    api_key_environment_variable: str
    selected_count: int
    submitted_count: int
    skipped_count: int
    errors: tuple[str, ...]
    rows: tuple[VirusTotalFindingSummaryRow, ...]
    write_normalized_results: bool
    include_full_response: bool
    schema_version: str = VIRUSTOTAL_FINDINGS_SUMMARY_SCHEMA_VERSION

    def counts_record(self) -> dict[str, int]:
        return {
            "finding_count": len(self.rows),
            "selected_count": self.selected_count,
            "submitted_count": self.submitted_count,
            "skipped_count": self.skipped_count,
            "complete_count": sum(row.analysis_complete for row in self.rows),
            "incomplete_count": sum(not row.analysis_complete for row in self.rows),
            "malicious_engine_count": sum(row.malicious for row in self.rows),
            "suspicious_engine_count": sum(row.suspicious for row in self.rows),
            "disagreement_count": sum(row.disagreement_state.startswith("local_") for row in self.rows),
        }

    @property
    def semantic_digest(self) -> str:
        return canonical_json_sha256(self.core_record())

    def core_record(self) -> dict[str, object]:
        return {
            "api_key_environment_variable": self.api_key_environment_variable,
            "config_digest": self.config_digest,
            "counts": self.counts_record(),
            "errors": self.errors,
            "evidence_authority": "external_corroboration",
            "local_result_mutated": False,
            "projection_policy": {
                "external_only": True,
                "local_score_mutation": False,
                "local_verdict_mutation": False,
                "tag_mutation": False,
                "chain_mutation": False,
                "mitre_mutation": False,
                "learning_mutation": False,
                "unknown_is_negative": False,
            },
            "rows": tuple(row.summary_record() for row in self.rows),
            "scan_id": self.scan_id,
            "schema_version": self.schema_version,
            "snapshot_semantic_digest": self.snapshot_semantic_digest,
            "status": self.status,
        }

    def to_record(self) -> dict[str, object]:
        record = self.core_record()
        record["summary_semantic_digest"] = self.semantic_digest
        return record

    def normalized_results_record(self) -> dict[str, object]:
        rows = tuple(
            row.raw_record(include_full_response=self.include_full_response)
            for row in self.rows
        ) if self.write_normalized_results else ()
        core = {
            "config_digest": self.config_digest,
            "counts": self.counts_record(),
            "evidence_authority": "external_corroboration",
            "local_result_mutated": False,
            "normalized_rows_enabled": self.write_normalized_results,
            "results": rows,
            "scan_id": self.scan_id,
            "schema_version": VIRUSTOTAL_NORMALIZED_RESULTS_SCHEMA_VERSION,
            "snapshot_semantic_digest": self.snapshot_semantic_digest,
            "status": self.status,
        }
        core["results_semantic_digest"] = canonical_json_sha256(core)
        return core


def _row_from_source(local_results: object, source: object) -> VirusTotalFindingSummaryRow:
    if no_hook_mapping_items(source) is None:
        raise TypeError("virustotal_summary_source_row_invalid")
    artifact_path = _text(_mapping_get(source, "path", ""), "virustotal_summary_artifact_path_invalid")
    local_record = _local_record(local_results, artifact_path)
    content_sha256 = final_record_content_sha256(local_record, "virustotal_summary_content_sha256_invalid")
    published_sha = _mapping_get(source, "content_sha256")
    if published_sha is not None and exact_content_sha256(published_sha, "virustotal_summary_source_sha256_invalid") != content_sha256:
        raise RuntimeError("virustotal_summary_content_identity_mismatch:" + artifact_path)
    local_score = _score(_mapping_get(source, "umige_score", 0.0), "virustotal_summary_local_score_invalid")
    fallback_verdict = _text(_mapping_get(source, "umige_risk", "unknown"), "virustotal_summary_local_risk_invalid", maximum=128)
    local_verdict = _local_verdict(local_record, fallback_verdict)
    reporting_status = _text(_mapping_get(source, "reporting_status", "analysis_incomplete"), "virustotal_summary_reporting_status_invalid", maximum=128)
    analysis_status, malicious, suspicious, harmless, undetected, timeout, failure, type_unsupported = _engine_counts(_mapping_get(source, "summary"))
    submitted = _bool(_mapping_get(source, "submitted", False), "virustotal_summary_submitted_invalid")
    skipped = _bool(_mapping_get(source, "skipped", False), "virustotal_summary_skipped_invalid")
    completed = _bool(_mapping_get(source, "vt_completed", False), "virustotal_summary_completed_invalid", default=False)
    analysis_id = _text(_mapping_get(source, "analysis_id", ""), "virustotal_summary_analysis_id_invalid", allow_blank=True, maximum=512)
    permalink = _text(_mapping_get(source, "permalink", ""), "virustotal_summary_permalink_invalid", allow_blank=True, maximum=2048)
    error = _text(_mapping_get(source, "error", ""), "virustotal_summary_error_invalid", allow_blank=True, maximum=2048)
    selection_reason = _text(_mapping_get(source, "selection_reason", "local_high_or_malicious"), "virustotal_summary_selection_reason_invalid", maximum=256)
    full_response = _mapping_get(source, "full_response")
    return VirusTotalFindingSummaryRow(
        artifact_path=artifact_path,
        content_sha256=content_sha256,
        local_verdict=local_verdict,
        local_score=local_score,
        selection_reason=selection_reason,
        submitted=submitted,
        skipped=skipped,
        reporting_status=reporting_status,
        analysis_status=analysis_status,
        analysis_id=analysis_id,
        permalink=permalink,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        timeout=timeout,
        failure=failure,
        type_unsupported=type_unsupported,
        engine_total=malicious + suspicious + harmless + undetected + timeout + failure + type_unsupported,
        analysis_complete=completed,
        error=error,
        disagreement_state=_disagreement(local_verdict, analysis_status, completed, malicious, suspicious),
        full_response=full_response,
    )


def build_virustotal_findings_summary(
    *,
    scan_id: object,
    snapshot_semantic_digest: object,
    local_results: object,
    virustotal_result: VirusTotalReportingResult,
) -> VirusTotalFindingsSummary:
    scan_id_text = _text(scan_id, "virustotal_summary_scan_id_invalid", maximum=256)
    snapshot_digest = exact_content_sha256(snapshot_semantic_digest, "virustotal_summary_snapshot_digest_invalid")
    if type(virustotal_result) is not VirusTotalReportingResult:
        raise TypeError("virustotal_reporting_result_required")
    if virustotal_result.local_result_mutated:
        raise RuntimeError("virustotal_local_result_mutation_forbidden")
    if len(virustotal_result.results) > _MAX_ROWS:
        raise ValueError("virustotal_summary_row_limit_exceeded")
    rows = tuple(
        sorted(
            (_row_from_source(local_results, source) for source in virustotal_result.results),
            key=lambda row: (row.content_sha256, row.artifact_path, row.analysis_id, row.reporting_status),
        )
    )
    if len(rows) != virustotal_result.selected_count:
        raise RuntimeError("virustotal_summary_selected_row_count_mismatch")
    if sum(row.submitted for row in rows) != virustotal_result.submitted_count:
        raise RuntimeError("virustotal_summary_submitted_row_count_mismatch")
    if sum(row.skipped for row in rows) != virustotal_result.skipped_count:
        raise RuntimeError("virustotal_summary_skipped_row_count_mismatch")
    return VirusTotalFindingsSummary(
        scan_id=scan_id_text,
        snapshot_semantic_digest=snapshot_digest,
        status=virustotal_result.status,
        config_digest=virustotal_result.config_digest,
        api_key_environment_variable=virustotal_result.api_key_environment_variable,
        selected_count=virustotal_result.selected_count,
        submitted_count=virustotal_result.submitted_count,
        skipped_count=virustotal_result.skipped_count,
        errors=virustotal_result.errors,
        rows=rows,
        write_normalized_results=virustotal_result.write_normalized_results,
        include_full_response=virustotal_result.include_full_response,
    )


def virustotal_results_json_bytes(summary: VirusTotalFindingsSummary) -> bytes:
    if type(summary) is not VirusTotalFindingsSummary:
        raise TypeError("virustotal_findings_summary_required")
    return (json.dumps(summary.normalized_results_record(), sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def virustotal_findings_json_bytes(summary: VirusTotalFindingsSummary) -> bytes:
    if type(summary) is not VirusTotalFindingsSummary:
        raise TypeError("virustotal_findings_summary_required")
    return (json.dumps(summary.to_record(), sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def _md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def virustotal_findings_markdown_bytes(summary: VirusTotalFindingsSummary) -> bytes:
    counts = summary.counts_record()
    lines = [
        "# VirusTotal Findings Summary",
        "",
        f"- Scan ID: `{summary.scan_id}`",
        f"- Snapshot semantic digest: `{summary.snapshot_semantic_digest}`",
        f"- Summary semantic digest: `{summary.semantic_digest}`",
        f"- Reporting state: `{summary.status}`",
        f"- Selected / submitted / skipped: {summary.selected_count} / {summary.submitted_count} / {summary.skipped_count}",
        f"- Local/external disagreements: {counts['disagreement_count']}",
        "- Evidence authority: `external_corroboration`; local score/verdict/Tags/Chains/MITRE/learning are immutable.",
        "- Unknown, unavailable, and incomplete external states are not negative evidence.",
        "",
        "| SHA-256 | Local verdict | Score | Submission state | Analysis state | Malicious | Suspicious | Engines | Disagreement |",
        "|---|---|---:|---|---|---:|---:|---:|---|",
    ]
    for row in summary.rows:
        submission = "skipped" if row.skipped else "submitted" if row.submitted else row.reporting_status
        lines.append("| " + " | ".join((
            _md(row.content_sha256), _md(row.local_verdict), str(row.local_score), _md(submission),
            _md(row.analysis_status), str(row.malicious), str(row.suspicious), str(row.engine_total),
            _md(row.disagreement_state),
        )) + " |")
    lines.append("")
    return ("\n".join(lines) + "\n").encode("utf-8")


def virustotal_findings_csv_bytes(summary: VirusTotalFindingsSummary) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow((
        "artifact_path", "content_sha256", "local_verdict", "local_score", "selection_reason",
        "submitted", "skipped", "reporting_status", "analysis_status", "analysis_id", "permalink",
        "malicious", "suspicious", "harmless", "undetected", "timeout", "failure", "type_unsupported",
        "engine_total", "analysis_complete", "error", "disagreement_state", "evidence_authority",
        "local_result_mutated", "row_semantic_digest",
    ))
    for row in summary.rows:
        writer.writerow((
            row.artifact_path, row.content_sha256, row.local_verdict, row.local_score, row.selection_reason,
            row.submitted, row.skipped, row.reporting_status, row.analysis_status, row.analysis_id, row.permalink,
            row.malicious, row.suspicious, row.harmless, row.undetected, row.timeout, row.failure,
            row.type_unsupported, row.engine_total, row.analysis_complete, row.error, row.disagreement_state,
            row.evidence_authority, row.local_result_mutated, row.semantic_digest,
        ))
    return stream.getvalue().encode("utf-8")


def render_virustotal_publication(summary: VirusTotalFindingsSummary) -> tuple[tuple[str, bytes], ...]:
    if type(summary) is not VirusTotalFindingsSummary:
        raise TypeError("virustotal_findings_summary_required")
    return (
        ("virustotal_results.json", virustotal_results_json_bytes(summary)),
        ("virustotal_findings_summary.json", virustotal_findings_json_bytes(summary)),
        ("virustotal_findings_summary.md", virustotal_findings_markdown_bytes(summary)),
        ("virustotal_findings_summary.csv", virustotal_findings_csv_bytes(summary)),
    )


__all__ = (
    "VIRUSTOTAL_FINDING_SUMMARY_ROW_SCHEMA_VERSION",
    "VIRUSTOTAL_FINDINGS_SUMMARY_SCHEMA_VERSION",
    "VIRUSTOTAL_NORMALIZED_RESULTS_SCHEMA_VERSION",
    "VirusTotalFindingSummaryRow",
    "VirusTotalFindingsSummary",
    "build_virustotal_findings_summary",
    "render_virustotal_publication",
    "virustotal_findings_csv_bytes",
    "virustotal_findings_json_bytes",
    "virustotal_findings_markdown_bytes",
    "virustotal_results_json_bytes",
)
