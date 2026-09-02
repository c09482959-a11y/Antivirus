"""Scanner-owned binary micro-stage collectors."""
from __future__ import annotations

from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from typing import Callable

from Virus_Scan.scanners.binary_io import read_binary_file_bytes
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.binary_embedded_payloads import validated_embedded_payload_hits
from Virus_Scan.scanners.contracts import scanner_failure_evidence_tags
from Virus_Scan.contracts.no_hook_materialization import no_hook_text


def _decode_latin1(data: bytes) -> str:
    return bytes(data or b"").decode("latin1", errors="ignore")


def _micro_stage_field(field: str) -> str:
    if type(field) is str and field:
        return str.__str__(field)
    return "value"


def _micro_stage_reason(prefix: str, field: str, suffix: str = "") -> str:
    return prefix + _micro_stage_field(field) + suffix


def _is_exact_micro_stage_path(value: object) -> bool:
    return type(value) in (PurePosixPath, PureWindowsPath, PosixPath, WindowsPath)


def _micro_stage_text(value: object, *, field: str) -> tuple[str, str]:
    field_text = _micro_stage_field(field)
    return no_hook_text(
        value,
        missing_reason=_micro_stage_reason("missing_micro_stage_", field_text),
        unsupported_reason=_micro_stage_reason("unsafe_micro_stage_", field_text, "_rejected"),
    )


def _micro_stage_path_text(value: object, *, field: str) -> tuple[str, str]:
    field_text = _micro_stage_field(field)
    path_text = ""
    reason = ""
    if value is None:
        reason = _micro_stage_reason("missing_micro_stage_", field_text)
    elif type(value) is str:
        path_text = str.__str__(value)
    elif type(value) in (bytes, bytearray):
        try:
            path_text = bytes(value).decode("utf-8", "replace")
        except SCAN_CONTENT_ERRORS:
            reason = _micro_stage_reason("micro_stage_", field_text, "_decode_failed")
    elif _is_exact_micro_stage_path(value):
        try:
            path_text = PurePath.__str__(value)
        except SCAN_CONTENT_ERRORS:
            reason = _micro_stage_reason("micro_stage_", field_text, "_path_text_failed")
    else:
        reason = _micro_stage_reason("unsafe_micro_stage_", field_text, "_rejected")
    return path_text, reason


def _micro_stage_failure_tags(kind_text: str, reason: str) -> list[str]:
    stage = "micro_stage_" + kind_text if kind_text else "micro_stage_unsupported"
    return scanner_failure_evidence_tags(
        "binary",
        stage,
        ValueError(reason),
        [
            "scanner_failure_evidence_recorded",
            "binary_final_json_must_record",
            reason,
        ],
        state="degraded",
        error_category="binary_micro_stage_boundary_rejected",
        file_type="binary",
    )


def _contextual_binary_tags(text: str) -> list[str]:
    text_value, text_reason = _micro_stage_text(text, field="contextual_text")
    if text_reason:
        return _micro_stage_failure_tags("binary_context", text_reason)
    low = text_value.lower()
    tags: list[str] = []
    if "powershell" in low:
        tags.append("powershell_exec")
    if "cmd.exe" in low or "createprocess" in low or "process.start" in low:
        tags.append("process_exec")
    if "http://" in low or "https://" in low or "downloadstring" in low or "webclient" in low:
        tags.append("network_download")
    if "frombase64string" in low or "base64" in low:
        tags.append("encoded_payload_candidate")
    if "schtasks" in low or "scheduledtask" in low:
        tags.append("scheduled_task")
    return tags


def _pe_api_tags(text: str) -> list[str]:
    text_value, text_reason = _micro_stage_text(text, field="pe_api_text")
    if text_reason:
        return _micro_stage_failure_tags("pe_api", text_reason)
    low = text_value.lower()
    tags: list[str] = []
    if "writeprocessmemory" in low:
        tags.append("memory_write")
    if "virtualprotect" in low:
        tags.append("memory_protect")
    if "virtualalloc" in low:
        tags.append("memory_allocate")
    if "createremotethread" in low or "ntcreatethreadex" in low:
        tags.append("thread_execution")
    if ("memory_write" in tags and "thread_execution" in tags) or (
        "memory_write" in tags and "memory_protect" in tags and "thread_execution" in tags
    ):
        tags.append("process_injection")
    return tags


def _validated_micro_stage_payload_path(payload: object, kind_text: str) -> tuple[str, list[str]]:
    payload_path, path_reason = _micro_stage_path_text(payload, field="payload_path")
    if path_reason:
        return "", _micro_stage_failure_tags(kind_text, path_reason)
    return payload_path, []


def _collect_file_identity(payload: object, kind_text: str) -> list[str]:
    payload_path, failure_tags = _validated_micro_stage_payload_path(payload, kind_text)
    if failure_tags:
        return failure_tags
    target = Path(payload_path)
    extension = target.suffix.lower()
    data = read_binary_file_bytes(target, max_size=4096)
    tags: list[str] = []
    if data.startswith(b"MZ"):
        tags.append("pe_file")
    if extension == ".exe":
        tags.extend(["pe_exe", "executable_file"])
    elif extension == ".dll":
        tags.extend(["pe_dll", "dll_file"])
    return tags


def _collect_binary_context(payload: object, kind_text: str) -> list[str]:
    payload_path, failure_tags = _validated_micro_stage_payload_path(payload, kind_text)
    if failure_tags:
        return failure_tags
    data = read_binary_file_bytes(payload_path, max_size=2 * 1024 * 1024)
    return _contextual_binary_tags(_decode_latin1(data))


def _collect_binary_payload(payload: object, kind_text: str) -> list[str]:
    payload_path, failure_tags = _validated_micro_stage_payload_path(payload, kind_text)
    if failure_tags:
        return failure_tags
    data = read_binary_file_bytes(payload_path, max_size=64 * 1024 * 1024)
    return [tag for _offset, tag in validated_embedded_payload_hits(data, min_offset=32)]


def _collect_pickle_payload(payload: object, kind_text: str) -> list[str]:
    payload_path, failure_tags = _validated_micro_stage_payload_path(payload, kind_text)
    if failure_tags:
        return failure_tags
    read_binary_file_bytes(payload_path, max_size=64 * 1024 * 1024)
    return []


def _collect_pe_api(payload: object, kind_text: str) -> list[str]:
    payload_path, failure_tags = _validated_micro_stage_payload_path(payload, kind_text)
    if failure_tags:
        return failure_tags
    data = read_binary_file_bytes(payload_path, max_size=2 * 1024 * 1024)
    return _pe_api_tags(_decode_latin1(data))


def _collect_runtime_text(payload: object, kind_text: str) -> list[str]:
    payload_text, payload_reason = _micro_stage_text(payload, field="payload_text")
    if payload_reason:
        return _micro_stage_failure_tags(kind_text, payload_reason)
    return _contextual_binary_tags(payload_text)


MicroStageHandler = Callable[[object, str], list[str]]


def _micro_stage_handler(kind_text: str) -> MicroStageHandler | None:
    handler: MicroStageHandler | None = None
    if kind_text == "file_identity":
        handler = _collect_file_identity
    elif kind_text == "binary_context":
        handler = _collect_binary_context
    elif kind_text == "binary_payload":
        handler = _collect_binary_payload
    elif kind_text == "pickle_payload":
        handler = _collect_pickle_payload
    elif kind_text == "pe_api":
        handler = _collect_pe_api
    elif kind_text in {"runtime_context", "runtime_decoded", "js_exec"}:
        handler = _collect_runtime_text
    return handler


def micro_stage_collect(kind: object, payload: object, path: object = None) -> object:
    del path  # Explicitly unused contract parameters.
    kind_text, kind_reason = _micro_stage_text(kind, field="kind")
    if kind_reason:
        return _micro_stage_failure_tags("unsupported", kind_reason)
    handler = _micro_stage_handler(kind_text)
    if handler is None:
        return []
    try:
        tags = handler(payload, kind_text)
    except SCAN_CONTENT_ERRORS as exc:
        tags = scanner_failure_evidence_tags(
            "binary",
            "micro_stage_" + kind_text,
            exc,
            ["scanner_failure_evidence_recorded", "binary_final_json_must_record"],
            state="degraded",
            error_category="binary_micro_stage_failure",
            file_type="binary",
        )
    return list(tags or [])


__all__ = ("micro_stage_collect",)
