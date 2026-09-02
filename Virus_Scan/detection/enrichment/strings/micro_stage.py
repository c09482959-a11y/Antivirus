"""Canonical detection enrichment owner for micro-stage raw collectors."""

from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.detection.enrichment.strings.contextual.scan import (
    ContextualTagScanRequest,
    contextual_tag_scan,
)
from Virus_Scan.detection.enrichment.strings.contextual.decoded_payloads import decoded_payload_tags
from Virus_Scan.detection.enrichment.strings.contextual.js_execution_model import umige_js_execution_model_tags
from Virus_Scan.detection.enrichment.pe_analysis.static_payload import scan_static_payload_anomalies
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage
from Virus_Scan.detection.evidence.static_bytes import stage_read_bytes
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.enrichment.strings.raw_stage_strings import stage_decode_latin1
from Virus_Scan.detection.enrichment.strings.boundaries import enrichment_sequence
from Virus_Scan.detection.enrichment.text_boundary import detection_enrichment_text_or_empty


def _file_identity_micro_tags(payload: object, _path: object) -> list[object]:
    ext = get_scan_extension(payload)
    data = stage_read_bytes(payload, max_size=4096)
    tags: list[object] = []
    if data.startswith(b"MZ"):
        tags.append("pe_file")
    if ext == ".exe":
        tags.extend(("pe_exe", "executable_file"))
    elif ext == ".dll":
        tags.extend(("pe_dll", "dll_file"))
    return tags


def _binary_context_micro_tags(payload: object, _path: object) -> list[object]:
    data = stage_read_bytes(payload, max_size=2 * 1024 * 1024)
    text = stage_decode_latin1(data)
    return list(contextual_tag_scan(ContextualTagScanRequest(
        strings_blob=text, path=payload, source="binary", data=data, finalize=False
    )))


def _binary_payload_micro_tags(payload: object, _path: object) -> list[object]:
    data = stage_read_bytes(payload, max_size=64 * 1024 * 1024)
    text = stage_decode_latin1(data)
    return list(enrichment_sequence(scan_static_payload_anomalies(payload, data=data, strings_blob=text)))


def _pickle_payload_micro_tags(payload: object, _path: object) -> list[object]:
    stage_read_bytes(payload, max_size=64 * 1024 * 1024)
    return []


def _pe_api_micro_tags(payload: object, _path: object) -> list[object]:
    data = stage_read_bytes(payload, max_size=2 * 1024 * 1024)
    text = stage_decode_latin1(data).lower()
    tags: list[object] = []
    if "writeprocessmemory" in text:
        tags.append("memory_write")
    if "virtualprotect" in text:
        tags.append("memory_protect")
    if "virtualalloc" in text:
        tags.append("memory_allocate")
    if "createremotethread" in text or "ntcreatethreadex" in text:
        tags.append("thread_execution")
    if "memory_write" in tags and "thread_execution" in tags:
        tags.append("process_injection")
    return tags


def _runtime_context_micro_tags(payload: object, path: object) -> list[object]:
    values = contextual_tag_scan(ContextualTagScanRequest(
        strings_blob=payload, path=path, source="strings", finalize=False
    ))
    return list(enrichment_sequence(values))


def _runtime_decoded_micro_tags(payload: object, path: object) -> list[object]:
    values = decoded_payload_tags(payload, path=path, finalize=False)
    return list(enrichment_sequence(values))


def _js_exec_micro_tags(payload: object, path: object) -> list[object]:
    values = umige_js_execution_model_tags(payload, path=path, finalize=False)
    return list(enrichment_sequence(values))


_MICRO_STAGE_HANDLERS = (
    ("file_identity", _file_identity_micro_tags),
    ("binary_context", _binary_context_micro_tags),
    ("binary_payload", _binary_payload_micro_tags),
    ("pickle_payload", _pickle_payload_micro_tags),
    ("pe_api", _pe_api_micro_tags),
    ("runtime_context", _runtime_context_micro_tags),
    ("runtime_decoded", _runtime_decoded_micro_tags),
    ("js_exec", _js_exec_micro_tags),
)
_FILE_MICRO_STAGES = frozenset({"file_identity", "binary_context", "binary_payload", "pickle_payload", "pe_api"})


def _micro_stage_handler(kind: object) -> object:
    for known_kind, handler in _MICRO_STAGE_HANDLERS:
        if kind == known_kind:
            return handler
    return None


def micro_stage_collect(kind: object, payload: object, path: object = None) -> object:
    """Raw micro-layer collector used by pre-central detection enrichment."""
    tags: list[object] = []
    failure_context = payload if kind in _FILE_MICRO_STAGES else (path if path is not None else payload)
    try:
        handler = _micro_stage_handler(kind)
        if handler is not None:
            tags.extend(handler(payload, path))
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        stage_name = "micro_stage_" + (detection_enrichment_text_or_empty(kind) or "unknown")
        tags.extend(failure_tags_for_stage(stage_name, exc, context=failure_context))
    return list(tags)
