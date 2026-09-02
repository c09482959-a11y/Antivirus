"""Detection-owned string extraction and obfuscation helpers."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_plain_instance_dict,
    no_hook_sequence_items,
    no_hook_text,
)


def _safe_detection_text(value: object) -> str:
    """Return bounded text without invoking caller-owned hooks."""
    text, reason = no_hook_text(
        value,
        missing_reason="missing_detection_text",
        unsupported_reason="string_extraction_unsafe_text_rejected",
    )
    if reason:
        return "string_extraction_failure_evidence"
    return text


def _safe_detection_bool(value: object) -> bool:
    """Fail closed for unknown truthy/falsy values without ``bool(value)``."""
    if value is None:
        return False
    if type(value) is bool:
        return value
    if type(value) in (str, bytes, bytearray, tuple, list, set, frozenset):
        return len(value) != 0
    if no_hook_mapping_items(value) is not None:
        items = no_hook_mapping_items(value)
        return items is not None and len(items) != 0
    return True


def looks_like_base64_payload(text: object) -> bool:
    matches = re.findall(r"(?i)(?:[A-Za-z0-9+/]{80,}={0,2})", _safe_detection_text(text))
    return any(len(match) >= 120 for match in matches)


def normalize_obfuscated_text(blob: object) -> str:
    text = _safe_detection_text(blob)
    qlit = r"(['\"])([A-Za-z0-9_\-/.\\:]+)\1"
    try:
        pat = re.compile(qlit + r"\s*\+\s*" + qlit)
        previous = None
        while previous != text:
            previous = text
            text = pat.sub(lambda match: repr((match.group(2) or "") + (match.group(4) or "")), text)
        pat2 = re.compile(qlit + r"\s+" + qlit)
        previous = None
        while previous != text:
            previous = text
            text = pat2.sub(lambda match: repr((match.group(2) or "") + (match.group(4) or "")), text)
        text = re.sub(r"\\x([0-9a-fA-F]{2})", lambda match: chr(int(match.group(1), 16)), text)
        text = re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), text)
        text = re.sub(r"\s+", " ", text)
        return text.lower()
    except RECOVERABLE_RUNTIME_ERRORS:
        return text.lower()


def _literal_strings(raw: str) -> tuple[str, ...]:
    try:
        parsed = ast.parse(raw)
    except (SyntaxError, ValueError, TypeError, UnicodeError, RuntimeError):
        return ("literal_string_parse_unavailable", "failure_evidence_recorded")
    literals = tuple(
        node.value
        for node in ast.walk(parsed)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value
    )
    return literals[:256]


def _decoded_payload_record_mapping(record: object) -> dict[object, object] | None:
    items = no_hook_mapping_items(record)
    if items is not None:
        return dict(items)
    data = no_hook_plain_instance_dict(record)
    if data is not None:
        return data
    return None


def observed_decoded_payload_texts(decoded_payloads: object = None) -> tuple[str, ...]:
    """Return scanner-observed decoded payload text without probing objects.

    Detection must not call scanner payload decoders or caller-owned hooks.  This
    helper consumes only exact builtin containers, mapping proxies, or plain
    instances whose real instance dictionary has been proven safe by the canonical
    no-hook contract.
    """
    if decoded_payloads is None:
        return ()
    records = no_hook_sequence_items(decoded_payloads)
    if records == () and decoded_payloads is not None:
        return ("decoded_payload_observation_unavailable",)
    out: list[str] = []
    for record in records:
        record_map = _decoded_payload_record_mapping(record)
        if record_map is None:
            out.append("decoded_payload_observation_unavailable")
            continue
        text = _safe_detection_text(dict.get(record_map, "text"))
        failure_tags = dict.get(record_map, "failure_tags")
        if _safe_detection_bool(failure_tags):
            continue
        if text:
            out.append(text[:65536])
    return tuple(out[:16])


def build_extraction_view(strings_blob: object, path: object = None, decoded_payloads: object = None) -> str:
    raw = _safe_detection_text(strings_blob)
    parts: list[str] = [raw, normalize_obfuscated_text(raw)]
    suffix = Path(_safe_detection_text(path)).suffix.lower()
    if suffix in {".py", ".pyw", ".rpy", ".rpyw", ".js", ".txt"} or len(raw) <= 2_000_000:
        literal_view = "\n".join(_literal_strings(raw))
        if literal_view:
            parts.append(literal_view)
            parts.append(normalize_obfuscated_text(literal_view))
    for decoded in observed_decoded_payload_texts(decoded_payloads):
        parts.append(decoded[:65536])
        parts.append(normalize_obfuscated_text(decoded[:65536]))
    return "\n".join(part for part in parts if part)[:4_000_000]


__all__ = (
    "build_extraction_view",
    "looks_like_base64_payload",
    "normalize_obfuscated_text",
    "observed_decoded_payload_texts",
)
