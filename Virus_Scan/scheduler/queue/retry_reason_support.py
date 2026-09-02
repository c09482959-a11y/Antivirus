"""Canonical retry field/reason text helpers."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.field_name_support import queue_field_name


retry_field_name = queue_field_name


def retry_reason(field_name: object, suffix: str) -> str:
    """Return canonical scheduler retry rejection/acceptance reason text."""
    safe_suffix = str.__str__(suffix) if type(suffix) is str and suffix else "rejected"
    return "scheduler_retry_" + retry_field_name(field_name) + "_" + safe_suffix


__all__ = ("retry_field_name", "retry_reason")
