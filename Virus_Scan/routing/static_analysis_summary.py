"""Canonical construction and publication validation for static-analysis summaries."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import (
    exact_int_or_none,
    exact_text_or_none,
    no_hook_mapping_items,
    no_hook_sequence_items,
)
from Virus_Scan.contracts.static_program_analysis import (
    STATIC_ANALYSIS_STATUSES,
    STATIC_INTEGRITY_STATES,
    StaticProgramAnalysis,
)

STATIC_ANALYSIS_SUMMARY_FIELD = "static_program_analysis"
STATIC_ANALYSIS_SUMMARY_SCHEMA_VERSION = "static_program_analysis_summary_v1"
_SUMMARY_FIELDS = frozenset({
    "cache_source",
    "flow_edge_count",
    "integrity_status",
    "language",
    "limitations",
    "operation_count",
    "parser_digest",
    "parser_schema_version",
    "parser_status",
    "scanner_id",
    "semantic_digest",
    "summary_schema_version",
    "unavailable_reason",
    "unresolved_constructs",
})
_SUMMARY_STATUSES = frozenset((*STATIC_ANALYSIS_STATUSES, "not_applicable"))
_CACHE_SOURCES = frozenset({"computed", "not_applicable", "sqlite_cache"})
_MAX_ANALYSIS_ITEMS = 4096
_MAX_TEXT_ITEMS = 256
_HEX = frozenset("0123456789abcdef")


def _digest(value: object) -> str | None:
    text = exact_text_or_none(value)
    if text is None:
        return None
    lowered = text.lower()
    if lowered == "":
        return ""
    if len(lowered) != 64 or any(character not in _HEX for character in lowered):
        return None
    return lowered


def _text(value: object, *, allow_blank: bool = True) -> str | None:
    text = exact_text_or_none(value)
    if text is None or (not allow_blank and text == ""):
        return None
    return text


def _text_sequence(value: object) -> list[str] | None:
    items = no_hook_sequence_items(value)
    if len(items) > _MAX_TEXT_ITEMS:
        return None
    output: list[str] = []
    for item in items:
        text = _text(item, allow_blank=False)
        if text is None:
            return None
        output.append(text)
    return output


def empty_static_analysis_summary(*, status: str, reason: str = "") -> dict[str, object]:
    """Return the one exact non-applicable static-analysis summary record."""
    if status != "not_applicable" or type(reason) is not str:
        raise ValueError("static_analysis_empty_summary_invalid")
    return {
        "cache_source": "not_applicable",
        "flow_edge_count": 0,
        "integrity_status": "unavailable",
        "language": "",
        "limitations": [],
        "operation_count": 0,
        "parser_digest": "",
        "parser_schema_version": "",
        "parser_status": status,
        "scanner_id": "",
        "semantic_digest": "",
        "summary_schema_version": STATIC_ANALYSIS_SUMMARY_SCHEMA_VERSION,
        "unavailable_reason": reason,
        "unresolved_constructs": [],
    }


def build_static_analysis_summary(
    analysis: StaticProgramAnalysis,
    *,
    scanner_id: str,
    cache_source: str,
) -> dict[str, object]:
    """Build the one exact summary projection from the canonical analysis owner."""
    if type(analysis) is not StaticProgramAnalysis:
        raise TypeError("static_analysis_summary_analysis_required")
    if type(scanner_id) is not str or scanner_id == "":
        raise TypeError("static_analysis_summary_scanner_id_invalid")
    if type(cache_source) is not str or cache_source not in _CACHE_SOURCES - {"not_applicable"}:
        raise ValueError("static_analysis_summary_cache_source_invalid")
    return {
        "cache_source": cache_source,
        "flow_edge_count": len(analysis.flow_edges),
        "integrity_status": analysis.integrity_status,
        "language": analysis.language,
        "limitations": list(analysis.limitations),
        "operation_count": len(analysis.operations),
        "parser_digest": analysis.parser_digest,
        "parser_schema_version": analysis.parser_schema_version,
        "parser_status": analysis.parser_status,
        "scanner_id": scanner_id,
        "semantic_digest": analysis.semantic_digest,
        "summary_schema_version": STATIC_ANALYSIS_SUMMARY_SCHEMA_VERSION,
        "unavailable_reason": analysis.unavailable_reason,
        "unresolved_constructs": list(analysis.unresolved_constructs),
    }


def static_analysis_summary_record(value: object) -> dict[str, object] | None:
    """Validate and detach one exact summary without invoking caller-owned hooks."""
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    raw: dict[str, object] = {}
    for key, item in items:
        text_key = exact_text_or_none(key)
        if text_key is None or text_key in raw:
            return None
        raw[text_key] = item
    if set(raw) != _SUMMARY_FIELDS:
        return None

    cache_source = _text(raw["cache_source"], allow_blank=False)
    parser_status = _text(raw["parser_status"], allow_blank=False)
    integrity_status = _text(raw["integrity_status"], allow_blank=False)
    scanner_id = _text(raw["scanner_id"])
    language = _text(raw["language"])
    parser_schema = _text(raw["parser_schema_version"])
    parser_digest = _digest(raw["parser_digest"])
    semantic_digest = _digest(raw["semantic_digest"])
    unavailable_reason = _text(raw["unavailable_reason"])
    schema = _text(raw["summary_schema_version"], allow_blank=False)
    operation_count = exact_int_or_none(raw["operation_count"])
    flow_edge_count = exact_int_or_none(raw["flow_edge_count"])
    limitations = _text_sequence(raw["limitations"])
    unresolved = _text_sequence(raw["unresolved_constructs"])

    if (
        cache_source not in _CACHE_SOURCES
        or parser_status not in _SUMMARY_STATUSES
        or integrity_status not in STATIC_INTEGRITY_STATES
        or scanner_id is None
        or language is None
        or parser_schema is None
        or parser_digest is None
        or semantic_digest is None
        or unavailable_reason is None
        or schema != STATIC_ANALYSIS_SUMMARY_SCHEMA_VERSION
        or operation_count is None
        or flow_edge_count is None
        or not 0 <= operation_count <= _MAX_ANALYSIS_ITEMS
        or not 0 <= flow_edge_count <= _MAX_ANALYSIS_ITEMS
        or limitations is None
        or unresolved is None
    ):
        return None
    if parser_status == "not_applicable":
        if (
            cache_source != "not_applicable"
            or integrity_status != "unavailable"
            or scanner_id != ""
            or language != ""
            or parser_schema != ""
            or parser_digest != ""
            or semantic_digest != ""
            or operation_count != 0
            or flow_edge_count != 0
            or limitations
            or unresolved
        ):
            return None
    else:
        if cache_source == "not_applicable" or scanner_id == "" or semantic_digest == "":
            return None
        if parser_status == "complete" and integrity_status != "verified":
            return None
        if parser_status in {"failed", "unavailable"} and (operation_count or flow_edge_count):
            return None
    return {
        "cache_source": cache_source,
        "flow_edge_count": flow_edge_count,
        "integrity_status": integrity_status,
        "language": language,
        "limitations": limitations,
        "operation_count": operation_count,
        "parser_digest": parser_digest,
        "parser_schema_version": parser_schema,
        "parser_status": parser_status,
        "scanner_id": scanner_id,
        "semantic_digest": semantic_digest,
        "summary_schema_version": schema,
        "unavailable_reason": unavailable_reason,
        "unresolved_constructs": unresolved,
    }


__all__ = (
    "STATIC_ANALYSIS_SUMMARY_FIELD",
    "STATIC_ANALYSIS_SUMMARY_SCHEMA_VERSION",
    "build_static_analysis_summary",
    "empty_static_analysis_summary",
    "static_analysis_summary_record",
)
