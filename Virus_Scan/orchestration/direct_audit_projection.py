"""Canonical per-record direct audit projection before final compaction."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PosixPath, WindowsPath

from Virus_Scan.cli.exit_codes import exit_code_for_score
from Virus_Scan.contracts.no_hook_materialization import (
    exact_bool_or_none,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.contracts.retained_scan_result import (
    retained_publication_record,
    retained_result_marker_present,
)


_CONTEXTUAL_PAYLOAD_ENGINES = frozenset({"embedded_pe_payload", "embedded_zip_payload"})
_CONTEXTUAL_PAYLOAD_TAGS = frozenset({"polyglot_artifact", "embedded_pe_payload", "embedded_zip_payload"})
_REQUIRED_ROUTING_EVIDENCE_KEYS = frozenset({
    "container_engine",
    "artifact_engine",
    "declared_extension",
    "sniffed_type",
    "effective_analysis_engine",
    "baseline_key",
    "extension_baseline",
    "contextual_baseline",
    "fingerprint_evidence",
})
_OWNED_PATH_TYPES = (Path, PosixPath, WindowsPath)


@dataclass(frozen=True, slots=True)
class DirectAuditProjectionContext:
    scheduler_mode: str
    requested_engine: str
    yara_enabled: bool

    def __post_init__(self) -> None:
        if type(self.scheduler_mode) is not str or not self.scheduler_mode:
            raise TypeError("direct_audit_scheduler_mode_exact_text_required")
        if type(self.requested_engine) is not str or not self.requested_engine:
            raise TypeError("direct_audit_requested_engine_exact_text_required")
        if type(self.yara_enabled) is not bool:
            raise TypeError("direct_audit_yara_enabled_exact_bool_required")


def audit_safe_text(value: object, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_orchestration_text",
        unsupported_reason="unsafe_orchestration_text_rejected",
    )
    if not reason:
        return str.strip(text)
    if type(value) in _OWNED_PATH_TYPES:
        try:
            return str(value)
        except (OSError, ValueError, TypeError, RuntimeError):
            return default
    return default


def audit_safe_lower(value: object, default: str = "") -> str:
    text = audit_safe_text(value, default)
    return str.lower(text) if text else default


def audit_safe_bool(value: object, *, default: bool = False) -> bool:
    metric = exact_bool_or_none(value)
    if metric is not None:
        return metric
    if type(value) is int and type(value) is not bool:
        return value != 0
    text = audit_safe_lower(value)
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default is True


def audit_safe_float(value: object, default: float = 0.0) -> float:
    metric, _reason = no_hook_finite_float(value, default=default, allow_exact_text=True)
    return metric


def audit_mapping_get(mapping: object, key: str, default: object = None) -> object:
    if type(key) is not str:
        return default
    if type(mapping) is dict:
        return dict.get(mapping, key, default)
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for candidate_key, value in items:
        if type(candidate_key) is str and str.__eq__(candidate_key, key):
            return value
    return default


def audit_mapping_items(mapping: object) -> tuple[tuple[object, object], ...]:
    items = no_hook_mapping_items(mapping)
    return items if items is not None else ()


def audit_mapping_values(mapping: object) -> tuple[object, ...]:
    return tuple(value for _key, value in audit_mapping_items(mapping))


def audit_copy_mapping(mapping: object) -> dict[object, object]:
    out: dict[object, object] = {}
    for key, value in audit_mapping_items(mapping):
        if type(key) is str:
            out[str.__str__(key)] = value
    return out


def audit_text_sequence(value: object) -> tuple[str, ...]:
    items = no_hook_mapping_items(value)
    candidates = tuple(key for key, _item in items) if items is not None else no_hook_sequence_items(value)
    normalized: list[str] = []
    for item in candidates:
        text_value = audit_safe_lower(item)
        if text_value and text_value not in normalized:
            normalized.append(text_value)
    return tuple(normalized)


def _enforce_contextual_payload_record(record: dict[str, object]) -> None:
    tags = set(audit_text_sequence(audit_mapping_get(record, "tags")))
    effective = audit_safe_lower(audit_mapping_get(record, "effective_analysis_engine"))
    embedded = set(audit_text_sequence(audit_mapping_get(record, "sniffed_embedded_types")))
    has_contextual_payload = (
        bool(tags & _CONTEXTUAL_PAYLOAD_TAGS)
        or effective in _CONTEXTUAL_PAYLOAD_ENGINES
        or bool(embedded & {"pe", "zip"})
    )
    if not has_contextual_payload:
        return
    if "terminal_clean_asset_triage" in tags:
        record["fast_path"] = False
        record["passive_fast_asset"] = False
    current_score = audit_safe_float(audit_mapping_get(record, "score"), 0.0)
    if current_score < 25.0:
        record["score"] = 25.0
    classification = audit_safe_lower(audit_mapping_get(record, "classification"))
    if not classification:
        classification = audit_safe_lower(audit_mapping_get(record, "class"))
    if classification in {"", "clean", "benign", "benign_clean", "asset", "media", "image", "passive_asset"}:
        record["classification"] = "low_confidence"
        record["class"] = "low_confidence"
        record["confidence"] = max(audit_safe_float(audit_mapping_get(record, "confidence"), 0.0), 0.55)
    explanation = audit_copy_mapping(audit_mapping_get(record, "explanation"))
    reasons = list(audit_text_sequence(audit_mapping_get(explanation, "reasons")))
    evidence = list(audit_text_sequence(audit_mapping_get(record, "decoded_evidence_snippets")))
    if "pe" in embedded or effective == "embedded_pe_payload" or "embedded_pe_payload" in tags:
        line = "EmbeddedPayload: PE payload marker observed inside declared media/container artifact"
        if line not in evidence:
            evidence.append(line)
        if line not in reasons:
            reasons.append(line)
    if "zip" in embedded or effective == "embedded_zip_payload" or "embedded_zip_payload" in tags:
        line = "EmbeddedPayload: ZIP/archive payload marker observed inside declared media/container artifact"
        if line not in evidence:
            evidence.append(line)
        if line not in reasons:
            reasons.append(line)
    record["decoded_evidence_snippets"] = evidence
    record["exit_code"] = exit_code_for_score(audit_mapping_get(record, "score", 0.0), had_error=False)
    explanation["reasons"] = reasons
    explanation["classification"] = audit_mapping_get(record, "classification")
    explanation["score"] = audit_mapping_get(record, "score")
    explanation["exit_code"] = record["exit_code"]
    record["explanation"] = explanation


def project_direct_audit_record(
    path: object,
    record: object,
    context: DirectAuditProjectionContext,
) -> tuple[str, object]:
    """Project one result through the exact direct-audit contract."""
    path_text = audit_safe_text(path)
    if type(record) is not dict:
        output_path = path_text or audit_safe_text(audit_mapping_get(record, "file"), "unknown_result_path") or "unknown_result_path"
        return output_path, record
    item = audit_copy_mapping(record)
    file_path = audit_safe_text(audit_mapping_get(item, "file"))
    if not file_path:
        file_path = audit_safe_text(audit_mapping_get(item, "path"))
    if not file_path:
        file_path = audit_safe_text(audit_mapping_get(item, "node"))
    if not file_path:
        file_path = path_text
    item.setdefault("file", file_path)
    item.setdefault("path", file_path)
    item.setdefault("extension", get_scan_extension(file_path).lstrip("."))
    missing_evidence = sorted(key for key in _REQUIRED_ROUTING_EVIDENCE_KEYS if key not in item)
    if missing_evidence:
        raise ValueError(
            "reporting received result without canonical routing evidence: "
            + ",".join(missing_evidence)
            + " file="
            + file_path
        )
    detected_engine = audit_safe_lower(audit_mapping_get(item, "detected_engine"))
    artifact_for_detection = audit_safe_lower(audit_mapping_get(item, "artifact_engine"))
    container_engine = audit_safe_lower(audit_mapping_get(item, "container_engine"))
    if artifact_for_detection and artifact_for_detection not in {"other", "unknown"}:
        resolved_detection_engine = artifact_for_detection
    elif detected_engine == "media":
        resolved_detection_engine = "media"
    elif container_engine not in {"other", "unknown", ""}:
        resolved_detection_engine = container_engine
    elif detected_engine and detected_engine != "unknown":
        resolved_detection_engine = detected_engine
    else:
        resolved_detection_engine = "other"
    item["detected_engine"] = resolved_detection_engine
    item.setdefault(
        "expected_engine",
        context.requested_engine if context.requested_engine != "auto" else None,
    )
    item.setdefault("effective_analysis_engine", audit_mapping_get(item, "effective_analysis_engine"))
    _enforce_contextual_payload_record(item)
    item["scheduler_mode"] = context.scheduler_mode
    item["yara_enabled"] = context.yara_enabled
    detector_errors = list(audit_text_sequence(audit_mapping_get(item, "detector_errors")))
    error_text = audit_safe_text(audit_mapping_get(item, "error"))
    item.setdefault("errors", detector_errors or ([] if not error_text else [error_text]))
    item.setdefault("warnings", list(audit_text_sequence(audit_mapping_get(item, "warnings"))))
    item.setdefault("worker_id", audit_mapping_get(item, "worker_id"))
    if "scan_duration_seconds" not in item and "slow_file_seconds" in item:
        item["scan_duration_seconds"] = audit_mapping_get(item, "slow_file_seconds")
    return file_path or path_text or "unknown_result_path", item


def project_direct_audit_results(
    results: object,
    context: DirectAuditProjectionContext,
) -> dict[str, object]:
    annotated: dict[str, object] = {}
    for path, record in audit_mapping_items(results):
        if retained_result_marker_present(record):
            publication = retained_publication_record(record)
            output_path = (
                audit_safe_text(audit_mapping_get(publication, "file"))
                or audit_safe_text(audit_mapping_get(publication, "path"))
                or audit_safe_text(path)
                or "unknown_result_path"
            )
            annotated[output_path] = record
            continue
        output_path, projected = project_direct_audit_record(path, record, context)
        annotated[output_path] = projected
    return annotated


__all__ = (
    "DirectAuditProjectionContext",
    "audit_mapping_get",
    "audit_mapping_items",
    "audit_mapping_values",
    "audit_safe_bool",
    "audit_safe_float",
    "audit_safe_lower",
    "audit_safe_text",
    "audit_text_sequence",
    "project_direct_audit_record",
    "project_direct_audit_results",
)
