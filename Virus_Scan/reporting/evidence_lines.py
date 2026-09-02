"""Public compact human evidence line rendering contract."""

from pathlib import Path

from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.reporting.evidence_line_extractors import (
    EvidenceLineContext,
    add_behavior_rule_lines,
    add_decode_lines,
    add_embedded_payload_lines,
    add_pickle_lines,
    add_url_lines,
    add_yara_lines,
)
from Virus_Scan.reporting.evidence_line_text import (
    raw_sample_text,
    safe_report_int,
    safe_report_mapping_get,
    safe_report_path_text,
    safe_report_sequence,
    safe_report_text,
)
from Virus_Scan.runtime.api import record_suppressed_failure


def _safe_tag_set(value: object) -> object:
    tags = set()
    for tag in safe_report_sequence(value, max_items=512):
        text = safe_report_text(tag, limit=120).lower()
        if text:
            tags.add(text)
    return tags


def _first_safe_report_sequence(*values: object) -> object:
    """Return the first non-empty exact builtin report sequence without truthiness hooks."""
    for value in values:
        sequence = safe_report_sequence(value, max_items=512)
        if len(sequence) > 0:
            return sequence
    return ()


def cli_human_evidence_lines(path: object, result: object, max_lines: object=14) -> object:
    """Build short MEDIUM+ CLI evidence lines for human triage."""
    lines = []
    seen = set()
    try:
        tags = _safe_tag_set(safe_report_mapping_get(result, "tags"))
        evidence = {}
        evidence_blob = safe_report_mapping_get(evidence, "strings_blob")
        strings_blob = safe_report_text(evidence_blob)
        if not strings_blob:
            strings_blob = safe_report_text(safe_report_mapping_get(result, "strings_blob"))
        if not strings_blob:
            strings_blob = _read_cli_sample_text(path)
        raw_text = raw_sample_text(evidence, strings_blob)
        api = safe_report_mapping_get(result, "api")
        ordered = _first_safe_report_sequence(
            safe_report_mapping_get(result, "ordered_events"),
            safe_report_mapping_get(result, "behavior_timeline"),
            safe_report_mapping_get(api, "ordered_events"),
        )
        context = EvidenceLineContext(
            path=path,
            lines=lines,
            seen=seen,
            tags=tags,
            strings_blob=strings_blob,
            raw_text=raw_text,
            evidence=evidence,
            ordered=ordered,
        )
        add_url_lines(lines, seen, tags, strings_blob, raw_text)
        add_decode_lines(lines, seen, tags, strings_blob)
        add_embedded_payload_lines(context)
        add_pickle_lines(context)
        add_behavior_rule_lines(context)
        add_yara_lines(lines, seen, result, tags)
        return lines[: max(1, safe_report_int(max_lines, 14))]
    except TELEMETRY_FAILURE_ERRORS as exc:
        _record_cli_evidence_failure(exc)
        return []


def _read_cli_sample_text(path: object) -> object:
    try:
        path_text = safe_report_path_text(path)
        if not path_text:
            return ""
        raw_cli = Path(path_text).read_bytes()[:1500000]
        if isinstance(raw_cli, (bytes, bytearray)):
            return raw_cli.decode("latin1", errors="ignore")
        return safe_report_text(raw_cli)
    except TELEMETRY_FAILURE_ERRORS as exc:
        _record_cli_evidence_failure(exc)
        return ""


def _record_cli_evidence_failure(exc: object) -> None:
    try:
        record_suppressed_failure("cli_evidence_line_extraction", exc, domain="reporting")
    except TELEMETRY_FAILURE_ERRORS as reporting_exc:
        _ = reporting_exc


__all__ = ("cli_human_evidence_lines",)
