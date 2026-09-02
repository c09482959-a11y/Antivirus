"""No-hook raw collector dispatch support."""
from __future__ import annotations



from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name


class UnknownGlobalRawCollectorError(ValueError):
    """Scheduler-owned unknown collector failure."""


def unknown_collector_error(collector: object) -> UnknownGlobalRawCollectorError:
    text, reason = no_hook_text(collector, missing_reason="raw_collector_missing", unsupported_reason="raw_collector_rejected")
    if reason or text == "":
        text = "unsupported_" + no_hook_type_name(collector)
    return UnknownGlobalRawCollectorError("unknown_global_raw_collector:" + text)


__all__ = ("UnknownGlobalRawCollectorError", "unknown_collector_error")
