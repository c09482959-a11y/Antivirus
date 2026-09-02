"""Canonical queue phase ordering ownership.

Owns deterministic queue phase order validation. It does not inspect queue
files, mutate queue state, execute work, or write evidence.
"""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_text

_QUEUE_PHASE_ORDER_ITEMS = (
    ("planning", 0),
    ("enqueue", 1),
    ("dispatch", 2),
    ("claim", 3),
    ("collect", 4),
    ("recovery", 5),
    ("recover", 5),
    ("publish", 6),
    ("reconcile", 7),
    ("finalize", 8),
)


def _queue_phase_text(phase: object) -> str:
    text, reason = no_hook_text(phase, missing_reason="queue_phase_missing", unsupported_reason="queue_phase_rejected")
    return text if reason == "" and text else "unknown"


def queue_phase_order(phase: object) -> int:
    phase_name = _queue_phase_text(phase)
    for known_phase, phase_order in _QUEUE_PHASE_ORDER_ITEMS:
        if known_phase == phase_name:
            return int(phase_order)
    raise RuntimeError("unknown scheduler queue phase: " + phase_name)


def validate_queue_phase_transition(previous_phase: object, current_phase: object) -> bool:
    previous = _queue_phase_text(previous_phase)
    current = _queue_phase_text(current_phase)
    if queue_phase_order(current) < queue_phase_order(previous):
        raise RuntimeError("scheduler queue phase regression: " + previous + " -> " + current)
    return True
