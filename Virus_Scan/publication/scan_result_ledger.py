"""Bounded parent-owned structured scan-result ledger."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.contracts.worker_record import make_json_safe
from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS

SCAN_RESULT_PREFIX = "[SCAN_RESULT] "
SCAN_SUMMARY_PREFIX = "[SCAN_SUMMARY] "
FINAL_SCANLOG_EVENT_TYPES = ("SCAN", "YARA", "CHAIN", "MITRE", "CLUSTER", "VT", "SUMMARY", "REPORT_SET")
FINAL_SCANLOG_EVENT_PREFIXES = {event_type: "[" + event_type + "] " for event_type in FINAL_SCANLOG_EVENT_TYPES}
_MAX_SCANLOG_LINE = 1_000_000
_MAX_TAGS = 128
_MAX_MESSAGES = 16
_MAX_YARA_IDS = 64
_MAX_TEXT = 256


def _ledger_text(value: object) -> str:
    if type(value) is str:
        return str.__str__(value)[:_MAX_TEXT]
    if value is None:
        return ""
    if type(value) in (int, float, bool):
        return str.__str__(value)[:_MAX_TEXT]
    return "<" + no_hook_type_name(value) + ">"


def _mapping_value(record: object, key: str, default: object = None) -> object:
    if type(record) is dict:
        return dict.get(record, key, default)
    items = no_hook_mapping_items(record, allow_dict_subclass=True)
    if items is None:
        return default
    for item_key, item_value in items:
        if item_key == key:
            return item_value
    return default


def _first_value(record: object, keys: tuple[str, ...], default: object = None) -> object:
    for key in keys:
        value = _mapping_value(record, key)
        if value is not None:
            return value
    return default


def _record_sha(record: object) -> str:
    for key in ("sha256", "final_sha256", "source_sha256", "cache_sha256"):
        candidate = _ledger_text(_mapping_value(record, key, "")).strip().lower()
        if len(candidate) == 64 and all(item in "0123456789abcdef" for item in candidate):
            return candidate
    return ""


def _bounded_texts(value: object, limit: int) -> tuple[str, ...]:
    sequence = value if type(value) in (tuple, list) else ()
    return tuple(_ledger_text(item) for item in sequence[:limit])


def _yara_rule_ids(record: object) -> tuple[str, ...]:
    hits = _mapping_value(record, "yara_hits", ())
    sequence = hits if type(hits) in (tuple, list) else ()
    rules: list[str] = []
    for hit in sequence[:_MAX_YARA_IDS]:
        if type(hit) is str:
            rules.append(_ledger_text(hit))
        else:
            rules.append(_ledger_text(_first_value(hit, ("rule", "name", "identifier"), "")))
    return tuple(rule for rule in rules if rule)


def _ledger_json(value: object) -> str:
    return json.dumps(make_json_safe(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def canonical_record_digest(record: object) -> str:
    return hashlib.sha256(_ledger_json(record).encode("utf-8", errors="replace")).hexdigest()


def _score(record: object) -> float | None:
    value = _mapping_value(record, "score")
    if type(value) not in (int, float) or type(value) is bool:
        return None
    score = float(value)
    return score if math.isfinite(score) else None


def scan_result_payload(
    key: object,
    record: object,
    ordinal: int,
    *,
    record_digest: str | None = None,
) -> dict[str, object]:
    """Build one bounded ledger record from the authoritative final record."""
    key_text = _ledger_text(key)
    sample_id = _ledger_text(_mapping_value(record, "sample_id", key_text))
    stable_path = _ledger_text(_first_value(record, ("normalized_path", "input_file_path", "path", "file", "node"), key_text))
    classification = _ledger_text(_first_value(record, ("classification", "verdict", "class"), ""))
    payload = {
        "schema_version": "scan_result_ledger_v2",
        "ordinal": ordinal,
        "record_key": key_text,
        "sample_id": sample_id,
        "stable_path": stable_path,
        "sha256": _record_sha(record),
        "classification": classification,
        "score": _score(record),
        "final_status": _ledger_text(_mapping_value(record, "final_status", "")),
        "exit_code": _mapping_value(record, "exit_code"),
        "scheduler_mode": _ledger_text(_mapping_value(record, "scheduler_mode", "")),
        "worker_id": _ledger_text(_mapping_value(record, "worker_id", "")),
        "fast_path": _mapping_value(record, "fast_path"),
        "learn_eligible": _mapping_value(record, "learn_eligible"),
        "learning_reason": _ledger_text(_mapping_value(record, "learning_reason", "")),
        "tags": _bounded_texts(_mapping_value(record, "tags", ()), _MAX_TAGS),
        "yara_rule_ids": _yara_rule_ids(record),
        "errors": _bounded_texts(_mapping_value(record, "errors", ()), _MAX_MESSAGES),
        "warnings": _bounded_texts(_mapping_value(record, "warnings", ()), _MAX_MESSAGES),
        "retried": _mapping_value(record, "retried", False),
        "recovered": _mapping_value(record, "recovered", False),
        "timed_out": _mapping_value(record, "timed_out", False),
        "record_digest": record_digest or canonical_record_digest(record),
    }
    return payload


def _file_sha256(path: object) -> str:
    try:
        source = Path(_ledger_text(path))
        if not source.is_file():
            return ""
        digest = hashlib.sha256()
        with source.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except TELEMETRY_FAILURE_ERRORS:
        return ""


def _persistence_ok(status: object) -> bool:
    if status is None:
        return True
    if type(status) is dict:
        return dict.get(status, "ok") is True
    return status is True


def _ledger_digest(payloads: tuple[dict[str, object], ...]) -> str:
    logical = tuple((item["sample_id"], item["record_digest"]) for item in payloads)
    return hashlib.sha256(_ledger_json(logical).encode("utf-8")).hexdigest()


@dataclass(slots=True)
class ScanResultLedgerAccumulator:
    """Collect bounded ledger rows from the exact compact records being written."""

    payloads: list[dict[str, object]] = field(default_factory=list)
    final_records: list[tuple[str, dict[str, object]]] = field(default_factory=list)

    def observe(self, key: object, record: object) -> None:
        ordinal = len(self.payloads) + 1
        digest = canonical_record_digest(record)
        key_text = _ledger_text(key)
        safe_record = make_json_safe(record)
        if type(safe_record) is not dict:
            raise TypeError("scan_result_ledger_final_record_invalid")
        if any(existing_key == key_text for existing_key, _existing_record in self.final_records):
            raise ValueError("scan_result_ledger_duplicate_record_key")
        self.final_records.append((key_text, safe_record))
        self.payloads.append(
            scan_result_payload(key, safe_record, ordinal, record_digest=digest)
        )

    def publication_results(self) -> dict[str, object]:
        return {key: dict(record) for key, record in self.final_records}

    def publish(
        self,
        output_path: object,
        *,
        log_info: object,
        persistence_status: object = None,
        published_path: object = None,
    ) -> dict[str, object]:
        payloads = tuple(self.payloads)
        sample_ids = tuple(_ledger_text(item["sample_id"]) for item in payloads)
        unique_ids = frozenset(item for item in sample_ids if item)
        for payload in payloads:
            log_info(SCAN_RESULT_PREFIX + _ledger_json(payload))
        summary = {
            "schema_version": "scan_result_ledger_summary_v2",
            "record_count": len(payloads),
            "unique_sample_ids": len(unique_ids),
            "duplicate_sample_ids": len(sample_ids) - len(unique_ids),
            "missing_sample_ids": sum(1 for item in sample_ids if item == ""),
            "missing_sha256": sum(1 for item in payloads if item["sha256"] == ""),
            "final_json_path": _ledger_text(output_path if published_path is None else published_path),
            "final_json_sha256": _file_sha256(output_path),
            "ledger_digest": _ledger_digest(payloads),
            "persistence_ok": _persistence_ok(persistence_status),
            "persistence_status": make_json_safe(persistence_status),
        }
        summary["summary_digest"] = canonical_record_digest(summary)
        log_info(SCAN_SUMMARY_PREFIX + _ledger_json(summary))
        return summary


def emit_scan_result_ledger(
    results: Mapping[str, object],
    output_path: object,
    *,
    log_info: object,
    persistence_status: object = None,
) -> dict[str, object]:
    """Emit one parent-owned terminal record per authoritative result."""
    accumulator = ScanResultLedgerAccumulator()
    items = no_hook_mapping_items(results, allow_dict_subclass=True) or ()
    ordered = sorted(items, key=lambda item: _ledger_text(item[0]).replace("\\", "/").casefold())
    for key, record in ordered:
        accumulator.observe(key, record)
    return accumulator.publish(
        output_path,
        log_info=log_info,
        persistence_status=persistence_status,
    )

def scanlog_payload_from_line(line: str, prefix: str) -> dict[str, object] | None:
    if type(line) is not str or type(prefix) is not str or len(line) > _MAX_SCANLOG_LINE:
        return None
    index = line.find(prefix)
    if index < 0:
        return None
    try:
        payload = json.loads(line[index + len(prefix):].strip())
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return payload if type(payload) is dict else None


def parse_scanlog_ledger(lines: object) -> dict[str, object]:
    results: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []
    typed_events: dict[str, list[dict[str, object]]] = {event_type: [] for event_type in FINAL_SCANLOG_EVENT_TYPES}
    malformed_events: list[str] = []
    for line in lines if type(lines) in (list, tuple) else ():
        if type(line) is not str:
            continue
        result = scanlog_payload_from_line(line, SCAN_RESULT_PREFIX)
        if result is not None:
            results.append(result)
            continue
        summary = scanlog_payload_from_line(line, SCAN_SUMMARY_PREFIX)
        if summary is not None:
            summaries.append(summary)
            continue
        for event_type in FINAL_SCANLOG_EVENT_TYPES:
            prefix = FINAL_SCANLOG_EVENT_PREFIXES[event_type]
            if prefix not in line:
                continue
            event = scanlog_payload_from_line(line, prefix)
            if event is None:
                malformed_events.append(event_type)
            else:
                typed_events[event_type].append(event)
            break
    return {
        "results": results,
        "summaries": summaries,
        "typed_events": typed_events,
        "malformed_typed_events": tuple(malformed_events),
    }


__all__ = (
    "FINAL_SCANLOG_EVENT_PREFIXES",
    "FINAL_SCANLOG_EVENT_TYPES",
    "SCAN_RESULT_PREFIX",
    "SCAN_SUMMARY_PREFIX",
    "ScanResultLedgerAccumulator",
    "canonical_record_digest",
    "emit_scan_result_ledger",
    "parse_scanlog_ledger",
    "scan_result_payload",
    "scanlog_payload_from_line",
)
