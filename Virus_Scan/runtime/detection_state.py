"""Runtime-owned detection state.

Detection modules compute evidence and tag semantics.  Mutable scan evidence
and short-lived stage timelines are owned by an explicitly configured runtime
state object, not by module globals in the detection package.
"""
from __future__ import annotations

from collections import defaultdict, deque
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import RLock
from typing import NoReturn


class DetectionStateNotConfigured(RuntimeError):
    """Raised when detection state is used before runtime ownership is bound."""


_RUNTIME_DETECTION_STATE_TYPE_REQUIRED = "runtime detection state must be RuntimeDetectionState"


def _raise_runtime_detection_state_type_required() -> NoReturn:
    raise TypeError(_RUNTIME_DETECTION_STATE_TYPE_REQUIRED)


@dataclass
class RuntimeDetectionState:
    evidence_lock: RLock = field(default_factory=RLock)
    scan_evidence: dict[str, dict[str, object]] = field(default_factory=dict)
    stage_lock: RLock = field(default_factory=RLock)
    stage_events: dict[str, list[dict[str, object]]] = field(default_factory=lambda: defaultdict(list))
    temporal_events: dict[str, list[dict[str, object]]] = field(default_factory=lambda: defaultdict(list))
    sequence_history: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    temporal_cache: dict[str, object] = field(default_factory=dict)
    temporal_belief: dict[str, dict[str, object]] = field(
        default_factory=lambda: defaultdict(lambda: {'history': deque(maxlen=25), 'belief': 0.0})
    )


_DETECTION_STATE_BINDING: ContextVar[RuntimeDetectionState | None] = ContextVar(
    'umige_runtime_detection_state',
    default=None,
)


def configure_runtime_detection_state(state: RuntimeDetectionState) -> None:
    """Bind detection state explicitly for the current runtime context."""
    if not isinstance(state, RuntimeDetectionState):
        _raise_runtime_detection_state_type_required()
    _DETECTION_STATE_BINDING.set(state)


def detection_state() -> RuntimeDetectionState:
    """Return the runtime-owned detection state."""
    state = _DETECTION_STATE_BINDING.get()
    if state is None:
        exception_message = 'runtime detection state not configured'
        raise DetectionStateNotConfigured(exception_message)
    return state


__all__ = (
    'DetectionStateNotConfigured',
    'RuntimeDetectionState',
    'configure_runtime_detection_state',
    'detection_state',
)
