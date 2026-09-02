"""Routing-owned file I/O helpers for extension scan routing."""
from __future__ import annotations

from pathlib import Path
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.runtime.api import log_error
from Virus_Scan.utils.pathing import normalize_scan_path
from Virus_Scan.utils.stages import get_scan_extension


def stage_decode_latin1(data: object) -> object:
    """Decode scanner bytes with the historical routing latin-1 fallback."""
    if data is None:
        return ""
    if type(data) is bytes:
        return data.decode("latin1", errors="ignore")
    if type(data) is bytearray:
        return bytes(data).decode("latin1", errors="ignore")
    text, reason = no_hook_text(
        data,
        missing_reason="routing_stage_decode_missing",
        unsupported_reason="routing_stage_decode_rejected",
    )
    return "" if reason else text


def read_file_bytes(path: object, max_size: object=5_000_000) -> object:
    """Bounded routing-owned byte read that records explicit read failures."""
    resolved = normalize_scan_path(path, require_exists=True)
    try:
        with Path(resolved).open("rb") as handle:
            return handle.read(max_size)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error(
            "file read failed: ext="
            + get_scan_extension(path)
            + "; error="
            + no_hook_type_name(exc)
        )
        return b""


__all__ = ("read_file_bytes", "stage_decode_latin1")
