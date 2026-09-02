"""Bounded environment setting construction for in-memory timeouts."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_text, scheduler_float, scheduler_int, scheduler_text
from Virus_Scan.scheduler.timeout.inmemory_timeout_config_values import (
    MinimumConfigEvidenceRequest,
    coerce_float_config,
    coerce_int_config,
    record_minimum_if_needed,
    timeout_config_evidence,
)




def timeout_env_value(
    environ: Mapping[str, str], name: object, default: object
) -> tuple[str, tuple[Mapping[str, object], ...]]:
    setting_name = scheduler_evidence_text(
        name,
        missing_text="timeout_setting",
        field_name="timeout_setting",
    )
    default_text = scheduler_evidence_text(
        default,
        missing_text="timeout_default",
        field_name="timeout_default",
    )
    if type(environ) is not dict:
        return default_text, (
            timeout_config_evidence(
                setting=setting_name,
                raw_value=environ,
                default_value=default_text,
                error=ValueError("timeout_environment_mapping_rejected"),
            ),
        )
    raw_value = (
        dict.__getitem__(environ, setting_name)
        if dict.__contains__(environ, setting_name)
        else default_text
    )
    text, reason = scheduler_text(
        raw_value,
        replacement_text=default_text,
        unsupported_reason="timeout_env_value_rejected",
    )
    if reason or text == "":
        return default_text, (
            timeout_config_evidence(
                setting=setting_name,
                raw_value=raw_value,
                default_value=default_text,
                error=ValueError(reason or "timeout_env_value_blank"),
            ),
        )
    return text, ()


def bounded_float_setting(
    environ: Mapping[str, str],
    *,
    name: str,
    default: float,
    minimum: float,
) -> tuple[float, tuple[Mapping[str, object], ...]]:
    raw_value, evidence = timeout_env_value(environ, name, default)
    value, value_evidence = coerce_float_config(
        setting=name,
        raw_value=raw_value,
        default=default,
    )
    minimum_evidence = record_minimum_if_needed(
        MinimumConfigEvidenceRequest(
            evidence=value_evidence,
            setting=name,
            raw_value=raw_value,
            parsed_value=value,
            minimum_value=minimum,
            default_value=default,
        )
    )
    safe_minimum, _minimum_reason = scheduler_float(minimum, default=0.0)
    return (max(value, safe_minimum)), evidence + value_evidence + minimum_evidence


def bounded_int_setting(
    environ: Mapping[str, str],
    *,
    name: str,
    default: int,
    minimum: int,
) -> tuple[int, tuple[Mapping[str, object], ...]]:
    raw_value, evidence = timeout_env_value(environ, name, default)
    value, value_evidence = coerce_int_config(
        setting=name,
        raw_value=raw_value,
        default=default,
    )
    minimum_evidence = record_minimum_if_needed(
        MinimumConfigEvidenceRequest(
            evidence=value_evidence,
            setting=name,
            raw_value=raw_value,
            parsed_value=value,
            minimum_value=minimum,
            default_value=default,
        )
    )
    safe_minimum, _minimum_reason = scheduler_int(minimum, default=0)
    return (max(value, safe_minimum)), evidence + value_evidence + minimum_evidence


def base_file_timeout(
    per_file_timeout_sec: float | None,
) -> tuple[int, tuple[Mapping[str, object], ...]]:
    raw_value: object = per_file_timeout_sec
    if raw_value is None or (type(raw_value) is str and raw_value == ""):
        raw_value = 20
    value, evidence = coerce_int_config(
        setting="per_file_timeout_sec",
        raw_value=raw_value,
        default=20,
    )
    minimum_evidence = record_minimum_if_needed(
        MinimumConfigEvidenceRequest(
            evidence=evidence,
            setting="per_file_timeout_sec",
            raw_value=raw_value,
            parsed_value=value,
            minimum_value=1.0,
            default_value=20,
        )
    )
    return (max(value, 1)), evidence + minimum_evidence


__all__ = (
    "base_file_timeout",
    "bounded_float_setting",
    "bounded_int_setting",
    "timeout_env_value",
)
