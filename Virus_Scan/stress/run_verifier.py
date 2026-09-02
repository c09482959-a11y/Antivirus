"""Independent manifest, final, checkpoint, scanlog, and profile verifier."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from types import MappingProxyType

from Virus_Scan.publication.scan_result_ledger import canonical_record_digest, parse_scanlog_ledger
from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.stress.corpus_types import StressVerificationIssue, StressVerificationReport
from Virus_Scan.stress.execution_types import StressRunVerification
from Virus_Scan.stress.profile_verifier import profile_snapshot_digest, snapshot_profiles, verify_no_malicious_profile_learning

_ACCEPTABLE_SCANNER_EXIT_CODES = frozenset({3})

_FINAL_SCANLOG_EVENT_NAMES = MappingProxyType({
    "SCAN": "final_publication_snapshot",
    "YARA": "final_projection",
    "CHAIN": "final_projection",
    "MITRE": "final_projection",
    "CLUSTER": "final_projection",
    "VT": "final_projection",
    "SUMMARY": "combined_malicious_findings",
    "REPORT_SET": "publication_prepared",
})


def verify_final_scanlog_events(scanlog_path: object) -> tuple[str, ...]:
    path = Path(scanlog_path)
    parsed = parse_scanlog_ledger(path.read_text(encoding="utf-8", errors="strict").splitlines())
    errors: list[str] = []
    malformed = dict.get(parsed, "malformed_typed_events", ())
    if type(malformed) in (tuple, list) and malformed:
        errors.append("scanlog_typed_event_malformed:" + ",".join(str(item) for item in malformed))
    typed = dict.get(parsed, "typed_events")
    if type(typed) is not dict:
        return tuple(errors + ["scanlog_typed_event_index_missing"])
    finals: dict[str, dict[str, object]] = {}
    for event_type, expected_name in _FINAL_SCANLOG_EVENT_NAMES.items():
        rows = dict.get(typed, event_type, ())
        if type(rows) not in (list, tuple):
            errors.append("scanlog_typed_event_collection_invalid:" + event_type)
            continue
        matches = [row for row in rows if type(row) is dict and dict.get(row, "event") == expected_name]
        if len(matches) != 1:
            errors.append("scanlog_final_event_count_invalid:" + event_type + ":" + str(len(matches)))
            continue
        finals[event_type] = matches[0]
    identities = {
        (dict.get(row, "scan_id"), dict.get(row, "snapshot_semantic_digest"))
        for row in finals.values()
    }
    if finals and (len(identities) != 1 or any(type(scan_id) is not str or not scan_id or type(digest) is not str or len(digest) != 64 for scan_id, digest in identities)):
        errors.append("scanlog_final_event_identity_mismatch")
    cluster = finals.get("CLUSTER", {})
    if cluster and (dict.get(cluster, "evidence_authority") != "context_only" or dict.get(cluster, "eligible_for_confirmation") is not False or dict.get(cluster, "eligible_for_probability") is not False):
        errors.append("scanlog_cluster_authority_invalid")
    vt = finals.get("VT", {})
    if vt and (dict.get(vt, "evidence_authority") != "external_corroboration" or dict.get(vt, "local_result_mutated") is not False or dict.get(vt, "unknown_is_negative") is not False):
        errors.append("scanlog_virustotal_authority_invalid")
    mitre = finals.get("MITRE", {})
    if mitre and dict.get(mitre, "execution_observed") is not False:
        errors.append("scanlog_mitre_execution_scope_invalid")
    summary = finals.get("SUMMARY", {})
    if summary and (dict.get(summary, "combined_score") is not None or dict.get(summary, "unknown_is_negative") is not False):
        errors.append("scanlog_combined_summary_authority_invalid")
    report_set = finals.get("REPORT_SET", {})
    if report_set and (dict.get(report_set, "completion_state") != "prepared_not_activated" or dict.get(report_set, "activation_record_owner") != "latest.json"):
        errors.append("scanlog_report_set_activation_contract_invalid")
    return tuple(errors)


def _scanlog_has_typed_events(scanlog_path: Path) -> bool:
    parsed = parse_scanlog_ledger(scanlog_path.read_text(encoding="utf-8", errors="strict").splitlines())
    typed = dict.get(parsed, "typed_events")
    if type(typed) is dict and any(type(rows) in (list, tuple) and rows for rows in dict.values(typed)):
        return True
    malformed = dict.get(parsed, "malformed_typed_events", ())
    return type(malformed) in (list, tuple) and bool(malformed)



def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("stress_artifact_not_object:" + str(path))
    return value


def _manifest_cases(path: Path) -> tuple[dict[str, object], ...]:
    manifest = _load_object(path)
    cases = dict.get(manifest, "cases")
    if type(cases) is not list or dict.get(manifest, "total_samples") != len(cases):
        raise ValueError("stress_manifest_count_contract_failed")
    return tuple(item for item in cases if type(item) is dict)


def _record_index(records: dict[str, object]) -> tuple[dict[str, dict[str, object]], int, int]:
    indexed: dict[str, dict[str, object]] = {}
    duplicates = 0
    missing = 0
    for record in dict.values(records):
        if type(record) is not dict:
            missing += 1
            continue
        sample_id = dict.get(record, "sample_id")
        if type(sample_id) is not str or sample_id == "":
            missing += 1
            continue
        duplicates += int(sample_id in indexed)
        indexed[sample_id] = record
    return indexed, duplicates, missing


def _ledger_index(scanlog_path: Path) -> tuple[dict[str, dict[str, object]], int, tuple[dict[str, object], ...]]:
    parsed = parse_scanlog_ledger(scanlog_path.read_text(encoding="utf-8", errors="strict").splitlines())
    indexed: dict[str, dict[str, object]] = {}
    duplicates = 0
    for record in dict.get(parsed, "results", []):
        if type(record) is not dict:
            continue
        sample_id = dict.get(record, "sample_id")
        if type(sample_id) is not str or sample_id == "":
            continue
        duplicates += int(sample_id in indexed)
        indexed[sample_id] = record
    summaries = tuple(item for item in dict.get(parsed, "summaries", []) if type(item) is dict)
    return indexed, duplicates, summaries


def _checkpoint_record(checkpoint: dict[str, object], root: Path, relative_path: str) -> dict[str, object] | None:
    expected = (root / "corpus" / relative_path).resolve().as_posix().casefold()
    for key, record in dict.items(checkpoint):
        normalized = str(key).replace("\\", "/").casefold()
        if normalized == expected and type(record) is dict:
            return record
    return None


def _record_tags(record: dict[str, object]) -> frozenset[str]:
    tags = dict.get(record, "tags", ())
    if type(tags) not in (list, tuple):
        return frozenset()
    return frozenset(str(item) for item in tags if type(item) is str)


def _record_score(record: dict[str, object]) -> float | None:
    value = dict.get(record, "score")
    if type(value) not in (int, float) or type(value) is bool:
        return None
    score = float(value)
    return score if math.isfinite(score) else None


def _oracle_errors(case: dict[str, object], record: dict[str, object], source: str) -> tuple[str, ...]:
    sample_id = str(dict.get(case, "sample_id", ""))
    errors: list[str] = []
    classification = str(dict.get(record, "classification", dict.get(record, "verdict", "")))
    allowed = tuple(str(item) for item in dict.get(case, "expected_classifications", ()))
    if classification not in allowed:
        errors.append(sample_id + ":" + source + ":classification")
    score = _record_score(record)
    minimum = float(dict.get(case, "minimum_score", 0.0))
    maximum = float(dict.get(case, "maximum_score", 100.0))
    if score is None or score < minimum or score > maximum:
        errors.append(sample_id + ":" + source + ":score")
    tags = _record_tags(record)
    required = frozenset(str(item) for item in dict.get(case, "required_tags", ()))
    forbidden = frozenset(str(item) for item in dict.get(case, "forbidden_tags", ()))
    if not required.issubset(tags):
        errors.append(sample_id + ":" + source + ":required_tags")
    if tags & forbidden:
        errors.append(sample_id + ":" + source + ":forbidden_tags")
    return tuple(errors)


def _final_identity_errors(case: dict[str, object], record: dict[str, object]) -> tuple[str, ...]:
    sample_id = str(dict.get(case, "sample_id", ""))
    errors: list[str] = []
    if dict.get(record, "sha256", dict.get(record, "final_sha256")) != dict.get(case, "sha256"):
        errors.append(sample_id + ":final:sha256")
    path = str(dict.get(record, "normalized_path", dict.get(record, "input_file_path", ""))).replace("\\", "/")
    if not path.endswith(str(dict.get(case, "relative_path", ""))):
        errors.append(sample_id + ":final:path")
    if dict.get(record, "final_status") != dict.get(case, "expected_terminal_status"):
        errors.append(sample_id + ":final:terminal_status")
    if dict.get(record, "learn_eligible") is not False:
        errors.append(sample_id + ":final:learning_disposition")
    return tuple(errors)


def _ledger_errors(case: dict[str, object], final: dict[str, object], ledger: dict[str, object]) -> tuple[str, ...]:
    sample_id = str(dict.get(case, "sample_id", ""))
    errors = list(_oracle_errors(case, ledger, "scanlog"))
    if dict.get(ledger, "sha256") != dict.get(case, "sha256"):
        errors.append(sample_id + ":scanlog:sha256")
    if dict.get(ledger, "record_digest") != canonical_record_digest(final):
        errors.append(sample_id + ":scanlog:record_digest")
    return tuple(errors)


def _materialized_errors(root: Path, cases: tuple[dict[str, object], ...]) -> tuple[str, ...]:
    errors: list[str] = []
    for case in cases:
        sample_id = str(dict.get(case, "sample_id", ""))
        path = (root / "corpus" / str(dict.get(case, "relative_path", ""))).absolute()
        if path_contains_filesystem_alias(path) or not path.is_file():
            errors.append(sample_id + ":materialized:file")
            continue
        if path.stat().st_size != dict.get(case, "size_bytes") or _file_sha256(path) != dict.get(case, "sha256"):
            errors.append(sample_id + ":materialized:identity")
    return tuple(errors)


def _case_errors(
    root: Path,
    case: dict[str, object],
    final: dict[str, object] | None,
    checkpoint: dict[str, object] | None,
    ledger: dict[str, object] | None,
) -> tuple[str, ...]:
    sample_id = str(dict.get(case, "sample_id", ""))
    if final is None or checkpoint is None or ledger is None:
        missing = []
        if final is None:
            missing.append(sample_id + ":missing_final")
        if checkpoint is None:
            missing.append(sample_id + ":missing_checkpoint")
        if ledger is None:
            missing.append(sample_id + ":missing_scanlog")
        return tuple(missing)
    errors = list(_oracle_errors(case, final, "final"))
    errors.extend(_final_identity_errors(case, final))
    errors.extend(_oracle_errors(case, checkpoint, "checkpoint"))
    errors.extend(_ledger_errors(case, final, ledger))
    if _record_score(final) != _record_score(checkpoint) or _record_tags(final) != _record_tags(checkpoint):
        errors.append(sample_id + ":checkpoint:logical_mismatch")
    return tuple(errors)


def _scan_generation_dir(root: Path) -> Path:
    scan_root = root / "Scan Logs"
    candidates = tuple(sorted((scan_root / "runs").glob("*"))) + tuple(
        sorted((scan_root / ".staging").glob("*"))
    )
    directories = tuple(path for path in candidates if path.is_dir())
    if len(directories) != 1:
        raise ValueError("stress_scan_log_generation_invalid")
    return directories[0]


def verify_stress_run(root: Path, *, expected_count: int, scanner_exit_code: int) -> StressRunVerification:
    manifest_path = root / "manifests" / "malicious_manifest.json"
    generation = _scan_generation_dir(root)
    final_path = generation / "scan_results.json"
    checkpoint_path = generation / "scan_results.json.partial.checkpoint.json"
    scanlog_path = generation / "scanlog"
    cases = _manifest_cases(manifest_path)
    final_records = _load_object(final_path)
    checkpoint_records = _load_object(checkpoint_path)
    final_index, final_duplicates, missing_identity = _record_index(final_records)
    ledger_index, ledger_duplicates, summaries = _ledger_index(scanlog_path)
    errors = list(_materialized_errors(root, cases))
    if _scanlog_has_typed_events(scanlog_path):
        errors.extend(verify_final_scanlog_events(scanlog_path))
    oracle_pass_count = 0
    for case in cases:
        sample_id = str(dict.get(case, "sample_id", ""))
        checkpoint = _checkpoint_record(checkpoint_records, root, str(dict.get(case, "relative_path", "")))
        case_errors = _case_errors(root, case, dict.get(final_index, sample_id), checkpoint, dict.get(ledger_index, sample_id))
        errors.extend(case_errors)
        oracle_pass_count += int(not case_errors)
    profile_report = verify_no_malicious_profile_learning(root / "profiles", manifest_path)
    errors.extend(issue.reason + ":" + issue.detail for issue in profile_report.issues)
    summary = summaries[-1] if summaries else {}
    counts = (len(cases), len(final_records), len(checkpoint_records), len(ledger_index))
    if any(count != expected_count for count in counts):
        errors.append("pipeline_count_mismatch")
    if dict.get(summary, "persistence_ok") is not True or dict.get(summary, "record_count") != expected_count:
        errors.append("scanlog_summary_contract_failed")
    if scanner_exit_code not in _ACCEPTABLE_SCANNER_EXIT_CODES:
        errors.append("scanner_exit_code_unexpected")
    duplicate_count = final_duplicates + ledger_duplicates
    missing_count = missing_identity + sum(1 for case in cases if str(dict.get(case, "sample_id", "")) not in final_index or str(dict.get(case, "sample_id", "")) not in ledger_index)
    live_partials = tuple(generation.glob("*.partial"))
    snapshot = snapshot_profiles(root / "profiles")
    passed = not errors and not duplicate_count and not missing_count and not live_partials and oracle_pass_count == expected_count
    return StressRunVerification(
        passed, expected_count, len(cases), len(cases) - len(_materialized_errors(root, cases)), len(final_records),
        len(checkpoint_records), len(ledger_index), oracle_pass_count, missing_count, duplicate_count, len(errors),
        len(profile_report.issues), len(live_partials), scanner_exit_code, tuple(errors), _file_sha256(manifest_path),
        _file_sha256(final_path), _file_sha256(checkpoint_path), str(dict.get(summary, "ledger_digest", "")),
        profile_snapshot_digest(snapshot),
    )


def verify_malicious_scan_artifacts(
    *,
    final_json_path: object,
    scanlog_path: object,
    oracle_manifest_path: object,
    checkpoint_path: object = None,
) -> StressVerificationReport:
    cases = _manifest_cases(Path(oracle_manifest_path))
    final_records = _load_object(Path(final_json_path))
    final_index, duplicates, missing = _record_index(final_records)
    ledger_index, ledger_duplicates, _summaries = _ledger_index(Path(scanlog_path))
    issues: list[StressVerificationIssue] = []
    for case in cases:
        sample_id = str(dict.get(case, "sample_id", ""))
        final = dict.get(final_index, sample_id)
        ledger = dict.get(ledger_index, sample_id)
        if final is None or ledger is None:
            issues.append(StressVerificationIssue("artifacts", sample_id, "missing_record", sample_id))
            continue
        for error in _oracle_errors(case, final, "final") + _ledger_errors(case, final, ledger):
            issues.append(StressVerificationIssue("artifacts", sample_id, "oracle_mismatch", error))
    if checkpoint_path is not None and not Path(checkpoint_path).is_file():
        issues.append(StressVerificationIssue("checkpoint", "", "missing_checkpoint_evidence", str(checkpoint_path)))
    if duplicates + ledger_duplicates + missing:
        issues.append(StressVerificationIssue("artifacts", "", "identity_count_failure", str(duplicates + ledger_duplicates + missing)))
    return StressVerificationReport(not issues, len(cases), tuple(issues))


__all__ = ("verify_final_scanlog_events", "verify_malicious_scan_artifacts", "verify_stress_run")
