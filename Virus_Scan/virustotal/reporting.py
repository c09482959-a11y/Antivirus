"""Canonical post-scoring VirusTotal external-corroboration projection."""
from __future__ import annotations

from pathlib import Path
import time
import urllib.error

from Virus_Scan.cli.exit_codes import score_from_result
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.contracts.retained_scan_result import retained_publication_record, retained_result_marker_present
from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.reporting.risk_label import risk_label_from_score
from Virus_Scan.core.logging import emit_parent_scan_log_event
from Virus_Scan.publication.content_identity import final_record_content_sha256
from Virus_Scan.virustotal.client import VirusTotalClient, classify_error
from Virus_Scan.virustotal.config import VirusTotalConfig
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult
from Virus_Scan.virustotal.runtime import VirusTotalRuntimeSnapshot



def _mapping_get(mapping: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for candidate, value in items:
        if type(candidate) is str and str.__eq__(candidate, key):
            return value
    return default


def _text(value: object, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="virustotal_text_missing",
        unsupported_reason="virustotal_text_rejected",
    )
    if reason:
        return default
    return str.strip(text)


def _count(mapping: object, key: str, default: int = 0) -> int:
    value = _mapping_get(mapping, key, default)
    count, _reason = no_hook_exact_nonnegative_int(value, default=default, allow_exact_text=True)
    return count


def _metric(value: object, default: float = 0.0) -> float:
    metric, _reason = no_hook_finite_float(value, default=default, allow_exact_text=True)
    return metric


def _nested_mapping(mapping: object, *keys: str) -> object:
    current = mapping
    for key in keys:
        current = _mapping_get(current, key, {})
    return current if no_hook_mapping_items(current) is not None else {}


def _engine_total_from_summary(summary: object) -> int:
    if no_hook_mapping_items(summary) is None:
        return 0
    return sum(_count(summary, key) for key in (
        "malicious", "suspicious", "undetected", "harmless",
        "timeout", "failure", "type_unsupported",
    ))


class _VirusTotalQuotaGuard:
    def __init__(self, config: VirusTotalConfig) -> None:
        if type(config) is not VirusTotalConfig:
            raise TypeError("virustotal_quota_config_invalid")
        self.per_minute = config.upload_rate_limit_per_minute
        self.daily_limit = config.daily_upload_limit
        self.calls: list[float] = []
        self.daily_count = 0
        self.day_start = int(time.time() // 86400)

    def allow(self) -> tuple[bool, str]:
        now = time.time()
        current_day = int(now // 86400)
        if current_day != self.day_start:
            self.calls = []
            self.daily_count = 0
            self.day_start = current_day
        self.calls = [item for item in self.calls if now - item < 60.0]
        if self.daily_count >= self.daily_limit:
            return False, "daily_upload_limit"
        if len(self.calls) >= self.per_minute:
            return False, "upload_rate_limit_per_minute"
        return True, "ok"

    def record(self) -> None:
        self.calls.append(time.time())
        self.daily_count += 1


def _analysis_has_populated_results(report: object, summary: object | None = None) -> bool:
    try:
        owned_summary = _summarize_analysis(report) if summary is None else summary
        if str.lower(_text(_mapping_get(owned_summary, "status"))) != "completed":
            return False
        if _engine_total_from_summary(owned_summary) > 0:
            return True
        attributes = _nested_mapping(report, "data", "attributes")
        results = _mapping_get(attributes, "results")
        if no_hook_mapping_items(results) is None:
            results = _mapping_get(attributes, "last_analysis_results")
        items = no_hook_mapping_items(results)
        return items is not None and len(items) > 0
    except IO_CONFIGURATION_ERRORS as exc:
        record_suppressed_failure("virustotal_analysis_population_check_failed", exc, domain="reporting")
        return False


def _stats_signature(summary: object) -> tuple[int, ...] | None:
    try:
        return tuple(
            _count(summary, key)
            for key in (
                "malicious", "suspicious", "undetected", "harmless",
                "timeout", "failure", "type_unsupported",
            )
        )
    except IO_CONFIGURATION_ERRORS as exc:
        record_suppressed_failure("virustotal_stats_signature_failed", exc, domain="reporting")
        return None


def _poll_config(
    config: VirusTotalConfig,
    call_owner: object | None,
    sleep_owner: object | None,
    time_owner: object | None,
) -> dict[str, object]:
    if type(config) is not VirusTotalConfig:
        raise TypeError("virustotal_poll_config_invalid")
    clock = time.time if time_owner is None else time_owner
    if not callable(clock):
        raise TypeError("virustotal_poll_time_owner_invalid")
    caller = None if call_owner is None else call_owner
    sleeper = time.sleep if sleep_owner is None else sleep_owner
    if caller is not None and not callable(caller):
        raise TypeError("virustotal_poll_call_owner_invalid")
    if not callable(sleeper):
        raise TypeError("virustotal_poll_sleep_owner_invalid")
    deadline = clock() + config.poll_max_wait_sec if config.poll_max_wait_sec > 0 else None
    return {
        "call_owner": caller,
        "deadline": deadline,
        "bounded_attempts": config.poll_attempts,
        "interval": config.poll_interval_sec,
        "max_wait": config.poll_max_wait_sec,
        "sleep_owner": sleeper,
        "stable_required": config.poll_stable_checks,
        "time_owner": clock,
        "wait_full": config.wait_for_full_report,
    }


def _record_poll_flags(
    row: dict[str, object],
    *,
    status: str,
    populated: bool,
    stable_seen: int,
    stable_required: int,
    attempt: int,
) -> None:
    row["vt_completed"] = status == "completed"
    row["vt_stats_populated"] = populated
    row["vt_stats_stable"] = stable_seen >= stable_required
    row["vt_poll_attempts_used"] = attempt


def _emit_poll_status(
    row: object,
    attempt: int,
    status: str,
    engine_total: int,
    summary: object,
    stable_seen: int,
    stable_required: int,
    *,
    mirror_console: bool,
) -> None:
    emit_parent_scan_log_event(
        "VT",
        {
            "event": "poll",
            "file": _text(_mapping_get(row, "file")),
            "attempt": attempt,
            "analysis_status": status,
            "engine_total": engine_total,
            "malicious": _count(summary, "malicious"),
            "suspicious": _count(summary, "suspicious"),
            "stable_seen": stable_seen,
            "stable_required": stable_required,
        },
        mirror_console=mirror_console,
    )

def _poll_step(
    client: VirusTotalClient,
    analysis_id: str,
    row: dict[str, object],
    attempt: int,
    poll: dict[str, object],
    last_signature: object,
    stable_seen: int,
    print_to_cli: bool,
) -> tuple[object, object, object, object, int]:
    caller = poll["call_owner"]
    if caller is None:
        report, error = client.call_with_retries(client.get_analysis, analysis_id)
    else:
        report, error = caller(client, analysis_id)
    if error is not None:
        row["error"] = "VirusTotal " + _text(_mapping_get(error, "code"), "error") + ": " + _text(_mapping_get(error, "action"), "failed")
        return report, error, None, last_signature, stable_seen
    summary = _summarize_analysis(report)
    row["summary"] = summary
    status = _text(_mapping_get(summary, "status"), "unknown") or "unknown"
    populated = _analysis_has_populated_results(report, summary)
    signature = _stats_signature(summary)
    if status == "completed" and populated:
        stable_seen = stable_seen + 1 if signature == last_signature else 1
        last_signature = signature
    else:
        stable_seen = 0
    _emit_poll_status(
        row,
        attempt,
        status,
        _engine_total_from_summary(summary),
        summary,
        stable_seen,
        int(poll["stable_required"]),
        mirror_console=print_to_cli,
    )
    return report, None, (status, populated), last_signature, stable_seen


def _poll_terminal(
    row: dict[str, object],
    report: object,
    state: tuple[str, bool],
    stable_seen: int,
    attempt: int,
    poll: dict[str, object],
    print_to_cli: bool,
) -> tuple[object, object, bool]:
    status, populated = state
    stable_required = int(poll["stable_required"])
    if status == "completed" and populated and stable_seen >= stable_required:
        _record_poll_flags(row, status=status, populated=populated, stable_seen=stable_seen, stable_required=stable_required, attempt=attempt)
        return report, None, True
    deadline = poll["deadline"]
    clock = poll["time_owner"]
    if deadline is not None and clock() >= deadline:
        _record_poll_flags(row, status=status, populated=populated, stable_seen=stable_seen, stable_required=stable_required, attempt=attempt)
        row["vt_completed"] = False
        row["error"] = "VirusTotal full-result wait exceeded poll_max_wait_sec=" + float.__str__(float(poll["max_wait"]))
        emit_parent_scan_log_event(
            "VT",
            {
                "event": "analysis_timeout",
                "file": _text(_mapping_get(row, "file")),
                "analysis_status": status,
                "error": _text(_mapping_get(row, "error")),
            },
            mirror_console=print_to_cli,
        )
        return report, None, True
    if poll["wait_full"] is not True and attempt >= int(poll["bounded_attempts"]):
        _record_poll_flags(row, status=status, populated=populated, stable_seen=stable_seen, stable_required=stable_required, attempt=attempt)
        return report, None, True
    return report, None, False


def _vt_poll_until_full_results(
    client: VirusTotalClient,
    analysis_id: str,
    row: dict[str, object],
    *,
    print_to_cli: bool = True,
    call_owner: object | None = None,
    sleep_owner: object | None = None,
    time_owner: object | None = None,
) -> tuple[object, object]:
    if type(client) is not VirusTotalClient or type(analysis_id) is not str or type(row) is not dict:
        raise TypeError("virustotal_poll_owner_invalid")
    poll = _poll_config(client.config, call_owner, sleep_owner, time_owner)
    last_signature = None
    stable_seen = 0
    attempt = 0
    final_report = None
    while True:
        attempt += 1
        final_report, error, state, last_signature, stable_seen = _poll_step(
            client, analysis_id, row, attempt, poll, last_signature, stable_seen, print_to_cli
        )
        if error is not None:
            return final_report, error
        if state is None:
            return final_report, None
        final_report, error, done = _poll_terminal(
            row, final_report, state, stable_seen, attempt, poll, print_to_cli
        )
        if done:
            return final_report, error
        interval = float(poll["interval"])
        if interval > 0:
            poll["sleep_owner"](interval)


def _summarize_analysis(report: object) -> dict[str, object]:
    attributes = _nested_mapping(report, "data", "attributes")
    stats = _mapping_get(attributes, "stats", {})
    if no_hook_mapping_items(stats) is None:
        stats = _mapping_get(attributes, "last_analysis_stats", {})
    status = _text(_mapping_get(attributes, "status"), "unknown") or "unknown"
    return {
        "status": status,
        "malicious": _count(stats, "malicious"),
        "suspicious": _count(stats, "suspicious"),
        "undetected": _count(stats, "undetected"),
        "harmless": _count(stats, "harmless"),
        "timeout": _count(stats, "timeout"),
        "failure": _count(stats, "failure"),
        "type_unsupported": _count(stats, "type-unsupported", _count(stats, "type_unsupported")),
    }


def _threshold_selected(score: float, risk: str, config: VirusTotalConfig) -> bool:
    label = str.lower(risk)
    if config.submit_malicious and (label == "malicious" or score >= 70.0):
        return True
    return config.submit_high and (label == "high" or score >= 50.0)


def _selected_candidates(results: object, config: VirusTotalConfig) -> list[tuple[str, object, float, str, str, str]]:
    selected: list[tuple[str, object, float, str, str, str]] = []
    items = no_hook_mapping_items(results)
    if items is None:
        return selected
    for path, result in items:
        public = retained_publication_record(result) if retained_result_marker_present(result) else result
        score = float(score_from_result(public))
        risk = risk_label_from_score(score)
        path_text = _text(path)
        if path_text != "" and _threshold_selected(score, risk, config):
            content_sha256 = final_record_content_sha256(public, "virustotal_selected_content_sha256_invalid")
            verdict = _text(
                _mapping_get(public, "classification", _mapping_get(public, "verdict", _mapping_get(public, "class", risk))),
                risk or "unknown",
            ) or (risk or "unknown")
            selected.append((path_text, result, score, risk, content_sha256, verdict))
    return selected


def _new_row(path: str, score: float, risk: str, content_sha256: str, local_verdict: str) -> dict[str, object]:
    return {
        "path": path,
        "content_sha256": content_sha256,
        "local_verdict": local_verdict,
        "selection_reason": "local_high_or_malicious",
        "file": Path(path).name,
        "umige_score": round(score, 2),
        "umige_risk": risk or "unknown",
        "submitted": False,
        "skipped": False,
        "error": None,
        "analysis_id": None,
        "summary": None,
        "evidence_authority": "external_corroboration",
    }


def _preupload_skip(
    row: dict[str, object],
    path: Path,
    config: VirusTotalConfig,
    stop_submissions: bool,
    quota: _VirusTotalQuotaGuard,
) -> tuple[bool, str]:
    if not path.is_file():
        row["skipped"] = True
        row["error"] = "file not found at original scan path"
        return True, "submission_failed"
    maximum = int(config.max_upload_mb * 1024 * 1024)
    if path.stat().st_size > maximum:
        row["skipped"] = True
        row["error"] = "file exceeds configured max_upload_mb=" + float.__str__(config.max_upload_mb)
        return True, "submission_failed"
    if stop_submissions:
        row["skipped"] = True
        row["error"] = "VirusTotal submissions stopped by prior API or quota state"
        return True, "rate_limited"
    allowed, reason = quota.allow()
    if not allowed:
        row["skipped"] = True
        row["error"] = "VirusTotal local rate limit: " + reason
        status = "quota_exhausted" if reason == "daily_upload_limit" else "rate_limited"
        return True, status
    quota.record()
    return False, "complete"


def _submit_candidate(
    client: VirusTotalClient,
    path: Path,
    row: dict[str, object],
) -> tuple[str, bool]:
    upload, error = client.call_with_retries(client.upload_file, path)
    if error is not None:
        action = _text(_mapping_get(error, "action"), "failed") or "failed"
        row["error"] = "VirusTotal " + _text(_mapping_get(error, "code"), "error") + ": " + action
        status = "quota_exhausted" if action == "quota_stop" else "rate_limited" if action == "rate_limit_wait" else "submission_failed"
        return status, action in {"quota_stop", "disable_vt", "rate_limit_wait"}
    row["submitted"] = True
    analysis_id = _text(_mapping_get(_mapping_get(upload, "data", {}), "id"))
    row["analysis_id"] = analysis_id or None
    if analysis_id == "":
        row["error"] = "VirusTotal response missing analysis identity"
        return "submission_failed", False
    if not client.config.poll_for_report:
        row["summary"] = {"status": "submitted_not_polled", "malicious": 0, "suspicious": 0}
        return "submitted_not_polled", False
    report, poll_error = _vt_poll_until_full_results(
        client,
        analysis_id,
        row,
        print_to_cli=client.config.print_to_cli,
    )
    if client.config.include_full_response and report is not None:
        row["full_response"] = report
    if poll_error is not None:
        action = _text(_mapping_get(poll_error, "action"), "failed")
        return "rate_limited" if action == "rate_limit_wait" else "analysis_incomplete", action in {"quota_stop", "disable_vt", "rate_limit_wait"}
    if row.get("vt_completed") is True:
        return "complete", False
    return "analysis_incomplete", False


def _process_candidates(
    selected: list[tuple[str, object, float, str, str, str]],
    client: VirusTotalClient,
) -> tuple[list[dict[str, object]], int, int, str, tuple[str, ...]]:
    rows: list[dict[str, object]] = []
    submitted = 0
    skipped = 0
    status = "complete"
    errors: list[str] = []
    quota = _VirusTotalQuotaGuard(client.config)
    stop_submissions = False
    for path_text, _result, score, risk, content_sha256, local_verdict in selected:
        row = _new_row(path_text, score, risk, content_sha256, local_verdict)
        try:
            should_skip, row_status = _preupload_skip(row, Path(path_text), client.config, stop_submissions, quota)
            if should_skip:
                skipped += 1
            else:
                row_status, stop_now = _submit_candidate(client, Path(path_text), row)
                stop_submissions = stop_submissions or stop_now
                submitted += 1 if row.get("submitted") is True else 0
            if row_status != "complete":
                status = row_status
            if row.get("error"):
                errors.append(_text(row.get("error"), "VirusTotal reporting error"))
        except urllib.error.HTTPError as exc:
            code, action, _payload = classify_error(exc)
            row["error"] = "VirusTotal " + code + ": " + action
            errors.append(_text(row["error"]))
            status = "rate_limited" if action == "rate_limit_wait" else "submission_failed"
            stop_submissions = stop_submissions or action in {"quota_stop", "disable_vt", "rate_limit_wait"}
        except IO_CONFIGURATION_ERRORS as exc:
            row["error"] = "VirusTotal error: " + no_hook_type_name(exc)
            errors.append(_text(row["error"]))
            status = "submission_failed"
        row["reporting_status"] = row_status
        if row.get("skipped") is True:
            emit_parent_scan_log_event(
                "VT",
                {
                    "event": "artifact",
                    "file": _text(row.get("file")),
                    "content_sha256": _text(row.get("content_sha256")),
                    "reporting_status": row_status,
                    "submitted": False,
                    "skipped": True,
                    "error": _text(row.get("error")),
                    "evidence_authority": "external_corroboration",
                },
                mirror_console=client.config.print_to_cli and client.config.print_skipped,
            )
        elif row.get("submitted") is True:
            summary = row.get("summary") if no_hook_mapping_items(row.get("summary")) is not None else {}
            emit_parent_scan_log_event(
                "VT",
                {
                    "event": "artifact",
                    "file": _text(row.get("file")),
                    "content_sha256": _text(row.get("content_sha256")),
                    "reporting_status": row_status,
                    "analysis_status": _text(_mapping_get(summary, "status"), "unavailable") or "unavailable",
                    "malicious": _count(summary, "malicious"),
                    "suspicious": _count(summary, "suspicious"),
                    "engine_total": _engine_total_from_summary(summary),
                    "submitted": True,
                    "skipped": False,
                    "evidence_authority": "external_corroboration",
                },
                mirror_console=client.config.print_to_cli and client.config.print_submitted,
            )
        rows.append(row)
    return rows, submitted, skipped, status, tuple(errors)


def _terminal_result(
    status: str,
    config: VirusTotalConfig | None,
    config_path: str,
    *,
    selected_count: int = 0,
    submitted_count: int = 0,
    skipped_count: int = 0,
    rows: tuple[object, ...] = (),
    errors: tuple[str, ...] = (),
) -> VirusTotalReportingResult:
    return VirusTotalReportingResult(
        status=status,
        config_digest="" if config is None else config.semantic_digest(),
        config_path=config_path,
        api_key_environment_variable="" if config is None else config.api_key_environment_variable,
        selected_count=selected_count,
        submitted_count=submitted_count,
        skipped_count=skipped_count,
        results=rows,
        errors=errors,
        write_normalized_results=True if config is None else config.write_normalized_results,
        include_full_response=False if config is None else config.include_full_response,
    )


def run_virustotal_reporting(
    results: object,
    runtime: VirusTotalRuntimeSnapshot,
) -> VirusTotalReportingResult:
    """Produce external corroboration from one startup-frozen runtime snapshot."""
    if type(runtime) is not VirusTotalRuntimeSnapshot:
        raise TypeError("virustotal_runtime_snapshot_required")
    config = runtime.config
    if runtime.status != "enabled":
        result = _terminal_result(
            runtime.status,
            config,
            runtime.config_path,
            errors=runtime.errors,
        )
    else:
        if type(config) is not VirusTotalConfig or type(runtime.client) is not VirusTotalClient:
            raise RuntimeError("virustotal_enabled_runtime_incomplete")
        result = _run_configured(results, config, runtime.config_path, runtime.client)
    emit_parent_scan_log_event(
        "VT",
        {
            "event": "summary",
            "status": result.status,
            "config_digest": result.config_digest,
            "selected_count": result.selected_count,
            "submitted_count": result.submitted_count,
            "skipped_count": result.skipped_count,
            "error_count": len(result.errors),
            "evidence_authority": "external_corroboration",
            "local_result_mutated": False,
        },
        mirror_console=False if config is None else config.print_to_cli,
    )
    return result

def _run_configured(
    results: object,
    config: VirusTotalConfig,
    config_path: str,
    client: VirusTotalClient,
) -> VirusTotalReportingResult:
    if type(client) is not VirusTotalClient or client.config != config:
        raise TypeError("virustotal_reporting_client_invalid")
    selected = _selected_candidates(results, config)
    if not selected:
        return _terminal_result("no_eligible_files", config, config_path)
    emit_parent_scan_log_event(
        "VT",
        {
            "event": "submission_batch",
            "selected_count": len(selected),
            "evidence_authority": "external_corroboration",
        },
        mirror_console=config.print_to_cli,
    )
    rows, submitted, skipped, status, errors = _process_candidates(selected, client)
    return _terminal_result(
        status,
        config,
        config_path,
        selected_count=len(selected),
        submitted_count=submitted,
        skipped_count=skipped,
        rows=tuple(rows),
        errors=errors,
    )


__all__ = ("_vt_poll_until_full_results", "run_virustotal_reporting")
