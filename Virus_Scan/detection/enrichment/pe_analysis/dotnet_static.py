""".NET PE enrichment scanner owner."""
from __future__ import annotations

from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.enrichment.strings.raw_stage_strings import scan_strings
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage
from Virus_Scan.detection.evidence.static_bytes import stage_read_bytes
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags

_DOTNET_MARKERS = ("mscoree.dll", "_cor_exe_main", "_cor_dll_main", "system.reflection", "system.runtime", "clr")


def scan_dotnet_file(path: object, *, finalize: object=True, include_strings: object=True) -> object:
    """PE/.NET scanner that keeps failures visible in tags/meta."""
    tags: list[str] = []
    meta = {"is_pe": False, "is_dotnet": False, "is_dll": False, "is_exe": False, "failures": []}
    try:
        ext = get_scan_extension(path)
        data = stage_read_bytes(path, max_size=5 * 1024 * 1024)
        text = data.decode("latin1", errors="ignore").lower()
        if data.startswith(b"MZ"):
            meta["is_pe"] = True
            tags.append("pe_file")
        if ext == ".dll":
            meta["is_dll"] = True
            tags += ["pe_dll", "dll_file"]
        if ext == ".exe":
            meta["is_exe"] = True
            tags += ["pe_exe", "executable_file"]
        if any(marker in text for marker in _DOTNET_MARKERS):
            meta["is_dotnet"] = True
            tags += ["dotnet", "dotnet_pe", "clr_runtime_present"]
        if "#strings" in text and "#us" in text and "#blob" in text:
            meta["is_dotnet"] = True
            tags += ["dotnet", "dotnet_metadata"]
        if "confuser" in text or "dnspy" in text or "costura" in text:
            tags += ["dotnet_obfuscated_or_packed", "packed_or_obfuscated"]
        if include_strings:
            tags.extend(scan_strings(text, path=path, finalize=finalize))
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        failure_tags = failure_tags_for_stage("dotnet_static_scan", exc, context=path)
        tags.extend(failure_tags)
        meta["failures"].append({"stage": "dotnet_static_scan", "error_category": type(exc).__name__, "message": str(exc)})
    if finalize:
        return (normalize_tags(tags), meta)
    return (list(tags or []), meta)
