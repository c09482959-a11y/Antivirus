"""Stage2636.11020 Phase 23 runtime-native function identity regressions."""
from __future__ import annotations

from functools import partial

import pytest

from Virus_Scan.contracts.runtime_function_identity import (
    RUNTIME_NATIVE_FUNCTION_TYPE,
    is_runtime_native_function,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_contracts import AttackClassifierSpec


def _module_function(_value: object = None) -> None:
    return None


class _CallableObject:
    def __call__(self, _value: object = None) -> None:
        return None

    def bound_method(self, _value: object = None) -> None:
        return None


def _classifier_spec(detector: object) -> AttackClassifierSpec:
    return AttackClassifierSpec(
        classifier_id="runtime_identity_test",
        version="1",
        family="test",
        detector=detector,
        score_ceiling=1.0,
        calibration_slope=1.0,
        calibration_midpoint=0.5,
        production_threshold=0.5,
    )


def test_runtime_function_identity_accepts_exact_module_functions() -> None:
    assert type(_module_function) is RUNTIME_NATIVE_FUNCTION_TYPE
    assert is_runtime_native_function(_module_function) is True
    assert _classifier_spec(_module_function).detector is _module_function


def test_runtime_function_identity_rejects_non_module_callables() -> None:
    owner = _CallableObject()
    rejected = (owner, owner.bound_method, partial(_module_function), len)
    assert all(is_runtime_native_function(value) is False for value in rejected)
    for value in rejected:
        with pytest.raises(TypeError, match="attack_classifier_function_required"):
            _classifier_spec(value)
