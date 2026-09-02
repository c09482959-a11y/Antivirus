"""Timeout-owned immutable evidence helpers for process-queue monitor policy."""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_error_detail, scheduler_text, scheduler_value_snapshot


def monitor_timeout_config_evidence(*, setting: str, raw_value: object, replacement_value: object, error: BaseException) -> Mapping[str, object]:
    setting_text, setting_reason = scheduler_text(
        setting,
        replacement_text="monitor_setting",
        unsupported_reason="monitor_setting_rejected",
    )
    if setting_reason != "" or not setting_text:
        setting_text = "monitor_setting"
    replacement_field = setting_text + "_replacement"
    return MappingProxyType(
        {
            "stage": "process_queue_monitor_timeout_config",
            "setting": setting_text,
            "raw_value": scheduler_value_snapshot(raw_value, field_name=setting_text),
            "replacement_value": scheduler_value_snapshot(replacement_value, field_name=replacement_field),
            "error_category": type(error).__name__,
            "error_source": "process_queue_monitor_policy.process_queue_monitor_policy",
            "detail": scheduler_error_detail(error),
            "timeout_failure": True,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_reproduce": True,
        }
    )


__all__ = (
    "monitor_timeout_config_evidence",
)
