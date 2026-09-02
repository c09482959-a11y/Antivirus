"""Scheduler queue JSON shared constants and degraded telemetry."""
from __future__ import annotations

import json

from Virus_Scan.runtime.api import record_suppressed_failure

QUEUE_JSON_EXCEPTIONS = (OSError, ValueError, TypeError, RuntimeError, AttributeError, json.JSONDecodeError)
QUEUE_JSON_DEGRADED_RECORD_FAILED = False
QUEUE_JSON_DEGRADED_RECORDED = True

def record_queue_json_degraded(where: str, exc: BaseException, *, domain: str = "persistence") -> bool:
    try:
        record_suppressed_failure(where, exc, domain=domain)
    except QUEUE_JSON_EXCEPTIONS:
        return QUEUE_JSON_DEGRADED_RECORD_FAILED
    return QUEUE_JSON_DEGRADED_RECORDED
