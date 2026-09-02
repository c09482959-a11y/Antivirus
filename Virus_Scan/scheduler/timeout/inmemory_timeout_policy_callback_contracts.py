"""Typed callback contracts for in-memory timeout policy evaluation."""
from __future__ import annotations

from collections.abc import Callable, Mapping

TimeoutPolicyRecord = Mapping[str, object]
TimeoutPolicyFailures = list[Mapping[str, object]]
TimeoutPolicySuppressedRecorder = Callable[[str, BaseException], object]
StartWaitBudget = Callable[[TimeoutPolicyRecord, float], float]
StagePreExecutionClassifier = Callable[[str], bool]

__all__ = (
    "StagePreExecutionClassifier",
    "StartWaitBudget",
    "TimeoutPolicyFailures",
    "TimeoutPolicyRecord",
    "TimeoutPolicySuppressedRecorder",
)
