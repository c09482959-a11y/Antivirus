"""Scanner-owned raw PE header extraction."""
from __future__ import annotations

from pathlib import Path
from pathlib import PurePath

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.scanners.binary_path_identity import get_binary_scan_extension
from Virus_Scan.scanners.binary_pe_bytes import pe_u32
from Virus_Scan.scanners.binary_pe_evidence import mark_pe_helper_error


PLR2004N64 = 64


def _binary_pe_path_text(path: object) -> object:
    if path is None:
        return ("", "missing_binary_pe_path")
    if type(path) is str:
        return (str.__str__(path), "")
    if type(path) in (bytes, bytearray):
        try:
            return (bytes(path).decode("utf-8", "replace"), "")
        except SCAN_CONTENT_ERRORS:
            return ("", "binary_pe_path_decode_failed")
    if isinstance(path, PurePath):
        try:
            return (PurePath.__str__(path), "")
        except SCAN_CONTENT_ERRORS:
            return ("", "binary_pe_path_text_failed")
    return no_hook_text(
        path,
        missing_reason="missing_binary_pe_path",
        unsupported_reason="unsafe_binary_pe_path_rejected",
    )


def _binary_pe_error_metadata(exc: object) -> object:
    text, reason = no_hook_text(
        exc,
        missing_reason="missing_binary_pe_error",
        unsupported_reason="unsafe_binary_pe_error_rejected",
    )
    if reason:
        return {"error_unavailable_reason": reason, "error_type": no_hook_type_name(exc)}
    return {"error": text}


def _binary_pe_unsupported_path_result(path: object, reason: object) -> object:
    return {
        "tags": [
            "pure_pe_scan_error",
            "binary_final_json_must_record",
            "scanner_failure_evidence_recorded",
            "scanner_failure_evidence:binary:global_raw_pure_pe_header",
        ],
        "meta": {
            "scanner_degraded": True,
            "binary_final_json_must_record": True,
            "path_unavailable_reason": reason,
            "path_type": no_hook_type_name(path),
        },
    }


def global_raw_pure_pe_header(path: object) -> object:
    """Cheap raw PE header collector used by scanner raw-stage contracts."""
    tags, meta = ([], {})
    path_text, path_reason = _binary_pe_path_text(path)
    if path_reason:
        return _binary_pe_unsupported_path_result(path, path_reason)
    try:
        with Path(path_text).open("rb") as fh:
            data = fh.read(4096)
        meta["is_pe"] = data.startswith(b"MZ")
        if data.startswith(b"MZ"):
            tags.append("pe_file")
            header_tags = _raw_pe_header_evidence(data)
            if header_tags:
                tags.extend(header_tags)
                meta["pe_header_degraded"] = True
            ext = get_binary_scan_extension(path_text)
            if ext == ".exe":
                tags += ["pe_exe", "executable_file"]
            elif ext == ".dll":
                tags += ["pe_dll", "dll_file"]
            elif ext == ".sys":
                tags += ["pe_sys", "driver_file"]
        meta["header_bytes"] = len(data or b"")
    except SCAN_CONTENT_ERRORS as exc:
        tags.append("pure_pe_scan_error")
        tags.extend(mark_pe_helper_error("global_raw_pure_pe_header", exc))
        meta.update(_binary_pe_error_metadata(exc))
        meta["scanner_degraded"] = True
        meta["binary_final_json_must_record"] = True
    return {"tags": tags, "meta": meta}


def _raw_pe_header_evidence(data: bytes) -> tuple[str, ...]:
    """Return evidence for MZ-like raw PE headers that are visibly malformed."""
    if len(data) < PLR2004N64:
        return tuple(mark_pe_helper_error("pe_header_parse", ValueError("truncated MZ/PE header")))
    pe_off = pe_u32(data, 60)
    if pe_off <= 0 or pe_off + 4 > len(data):
        return tuple(mark_pe_helper_error("pe_header_parse", ValueError("truncated PE signature offset")))
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return tuple(mark_pe_helper_error("pe_header_parse", ValueError("missing PE signature at header offset")))
    if pe_off + 24 > len(data):
        return tuple(mark_pe_helper_error("pe_header_parse", ValueError("truncated PE COFF header")))
    return ()


__all__ = ("global_raw_pure_pe_header",)
