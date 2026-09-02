"""No-hook scalar normalization for raw-stage input."""
from __future__ import annotations

from typing import Protocol

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scheduler.execution.exact_int_support import execution_exact_int


class RuntimeValueReader(Protocol):
    def runtime_value(self, key: str, default: object) -> object: ...



def exact_text(value: object, default_text: str, *, field_name: str) -> tuple[str, str]:
    text, reason = no_hook_text(value, missing_reason="raw_stage_" + field_name + "_missing", unsupported_reason="raw_stage_" + field_name + "_rejected")
    if reason == "" and text:
        return text, ""
    return default_text, reason


def exact_bool(value: object, default_value: bool, *, reason: str) -> tuple[bool, str]:
    if type(value) is bool:
        return value, ""
    if type(value) is int:
        return value != 0, ""
    if type(value) is str:
        text = str.__str__(value).strip().lower()
        if text in {"1", "true", "yes", "on", "enabled"}:
            return True, ""
        if text in {"0", "false", "no", "off", "disabled", ""}:
            return False, ""
    return default_value, reason


def runtime_cache_max(deps: RuntimeValueReader) -> int:
    value, _reason = execution_exact_int(deps.runtime_value("RAW_STAGE_EXEC_CACHE_MAX", 2048), 2048, minimum=1, reason="raw_stage_cache_max_rejected")
    return value


__all__ = ("RuntimeValueReader", "exact_bool", "exact_text", "runtime_cache_max")
