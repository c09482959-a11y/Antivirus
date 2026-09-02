"""Scanner-owned malformed image magic probes."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS

from Virus_Scan.scanners.config import load_scanner_limits_policy_snapshot
from Virus_Scan.scanners.contracts import scanner_contract_lower_token, scanner_contract_text

_SCANNER_LIMITS_POLICY = load_scanner_limits_policy_snapshot()

def _configured_magic_prefixes_by_extension() -> dict[str, tuple[bytes, ...]]:
    items = no_hook_mapping_items(_SCANNER_LIMITS_POLICY.image_magic_prefixes_by_extension)
    if items is None:
        return {}
    configured: dict[str, tuple[bytes, ...]] = {}
    for ext, prefixes in items:
        ext_text = scanner_contract_lower_token(ext, replacement="")
        if not ext_text.startswith(".") or type(prefixes) not in (tuple, list, set, frozenset):
            continue
        prefix_bytes = tuple(
            prefix_text.encode("latin1", errors="ignore")
            for prefix_text in (scanner_contract_text(prefix, replacement="") for prefix in prefixes)
            if prefix_text
        )
        if prefix_bytes:
            configured[ext_text] = prefix_bytes
    return configured


def fast_image_sample_malformed_status(path: object, sample: object) -> str:
    """Return explicit fast-image magic status without fail-open defaults."""
    try:
        data = bytes(sample or b"")
        if not data:
            return "empty_or_unchecked"
        ext = get_scan_extension(path)
        if ext == ".webp":
            return "malformed" if not (data.startswith(b"RIFF") and b"WEBP" in data[:16]) else "valid"
        prefixes = _configured_magic_prefixes_by_extension().get(ext)
        if prefixes:
            return "malformed" if not data.startswith(prefixes) else "valid"
    except SCAN_CONTENT_ERRORS:
        return "probe_error"
    return "empty_or_unchecked"


__all__ = ("fast_image_sample_malformed_status",)
