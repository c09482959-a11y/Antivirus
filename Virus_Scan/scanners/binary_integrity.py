"""Scanner-owned integrity markers for binary/entropy degraded outputs."""
from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name


def _binary_integrity_error_text(error: object) -> tuple[str, str]:
    text, reason = no_hook_text(
        error,
        missing_reason="missing_binary_integrity_error",
        unsupported_reason="unsafe_binary_integrity_error_rejected",
    )
    if reason:
        return ("", reason)
    return (text[:500], "")


def binary_degraded_scan_integrity(error: object = None, **extra: object) -> dict[str, object]:
    out: dict[str, object] = {
        "file_failed": True,
        "had_degraded_stage": True,
        "allow_learning": False,
    }
    if error is not None:
        error_text, error_reason = _binary_integrity_error_text(error)
        if error_reason:
            out["error_unavailable_reason"] = error_reason
            out["error_type"] = no_hook_type_name(error)
        else:
            out["error"] = error_text
    out.update(extra)
    return out


__all__ = ("binary_degraded_scan_integrity",)
