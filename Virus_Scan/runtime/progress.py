"""Canonical in-process progress callback ownership for scanner sub-stages.

This module owns only live in-memory progress callback state for the currently
executing worker thread/process.  It does not persist heartbeats and does not
create alternate scheduler paths; scheduler parents decide how callback events
become heartbeat/progress evidence.
"""
from __future__ import annotations

from threading import local
from typing import Callable

from Virus_Scan.runtime.governance_inputs import runtime_int, runtime_text

_PROGRESS_LOCAL = local()


def set_progress_callback(callback: Callable[[str, int, int], object] | None) -> None:
    """Set the current worker-thread progress callback."""
    _PROGRESS_LOCAL.callback = callback


def clear_progress_callback() -> None:
    """Clear the current worker-thread progress callback."""
    _PROGRESS_LOCAL.callback = None


def report_progress(stage: str = "scan", inc: int = 1, bytes_delta: int = 0) -> object:
    """Report a scanner progress checkpoint to the active scheduler callback."""
    stage_text, stage_issues = runtime_text(
        stage, field_name="progress_stage", default="input_rejected"
    )
    increment, inc_issues = runtime_int(
        inc, field_name="progress_increment", default=0
    )
    byte_count, byte_issues = runtime_int(
        bytes_delta, field_name="progress_bytes_delta", default=0
    )
    evidence = stage_issues + inc_issues + byte_issues
    record = {
        "stage": stage_text,
        "inc": increment,
        "bytes_delta": byte_count,
    }
    if evidence:
        record["runtime_input_rejected"] = True
        record["input_evidence"] = evidence
        return record
    try:
        callback = _PROGRESS_LOCAL.callback
    except AttributeError:
        callback = None
    if callable(callback):
        return callback(stage_text, increment, byte_count)
    return record


__all__ = ("clear_progress_callback", "report_progress", "set_progress_callback")
