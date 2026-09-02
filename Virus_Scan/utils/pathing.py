"""Direct-import-safe path/header helpers."""
from __future__ import annotations

from pathlib import Path
from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.utils.text_validation import text_boundary_value


def normalize_scan_path(path: object, *, require_exists: bool = False) -> str:
    p = text_boundary_value(path, unsupported=None)
    if p is None or p == "":
        if require_exists:
            raise FileNotFoundError("")
        return ""
    normalized = str(Path(p).expanduser().resolve())
    if require_exists and not Path(normalized).exists():
        raise FileNotFoundError(normalized)
    return normalized


def scan_path_text(path: object) -> str:
    text = ""
    try:
        p = normalize_scan_path(path, require_exists=False)
        text = p.replace('\\', '/').lower()
    except IO_CONFIGURATION_ERRORS:
        text = ""
    return text
