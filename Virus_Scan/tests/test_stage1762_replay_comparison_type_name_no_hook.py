from __future__ import annotations

import inspect

from Virus_Scan.models.api import replay_comparison_contracts as contracts


class HostileNameMeta(type):
    touched = 0

    def __getattribute__(cls, name):
        if name == "__name__":
            HostileNameMeta.touched += 1
            raise RuntimeError("metaclass __name__ hook must not execute")
        return super().__getattribute__(name)


class HostileReplayComparisonValue(metaclass=HostileNameMeta):
    touched = 0

    def __str__(self):
        HostileReplayComparisonValue.touched += 1
        raise RuntimeError("__str__ must not execute")

    def __repr__(self):
        HostileReplayComparisonValue.touched += 1
        raise RuntimeError("__repr__ must not execute")

    def __format__(self, spec):
        HostileReplayComparisonValue.touched += 1
        raise RuntimeError("__format__ must not execute")


class HostileKey(metaclass=HostileNameMeta):
    touched = 0

    def __str__(self):
        HostileKey.touched += 1
        raise RuntimeError("key __str__ must not execute")

    def __repr__(self):
        HostileKey.touched += 1
        raise RuntimeError("key __repr__ must not execute")

    def __format__(self, spec):
        HostileKey.touched += 1
        raise RuntimeError("key __format__ must not execute")


def _reset_hooks() -> None:
    HostileNameMeta.touched = 0
    HostileReplayComparisonValue.touched = 0
    HostileKey.touched = 0


def test_stage1762_compare_model_evidence_value_type_uses_no_hook_type_name() -> None:
    _reset_hooks()
    value = HostileReplayComparisonValue()

    record = contracts.compare_model_evidence(
        model_name=value,
        expected={"payload": value},
        actual={"payload": "safe"},
        reason=value,
    )
    materialized = contracts.materialize_model_evidence_comparison(record)

    assert HostileNameMeta.touched == 0
    assert HostileReplayComparisonValue.touched == 0
    assert materialized["model_name"] == "<unreadable_HostileReplayComparisonValue>"
    expected = materialized["expected"]
    assert expected["payload"]["value_type"] == "HostileReplayComparisonValue"
    assert expected["payload"]["unavailable_reason"] == "unreadable_public_contract_text"
    assert materialized["reason"] == "<unreadable_HostileReplayComparisonValue>"


def test_stage1762_compare_model_evidence_hostile_key_type_fallback_does_not_call_hooks() -> None:
    _reset_hooks()
    key = HostileKey()
    value = HostileReplayComparisonValue()

    record = contracts.compare_model_evidence(
        model_name="model",
        expected={key: value},
        actual={},
    )
    materialized = contracts.materialize_model_evidence_comparison(record)

    assert HostileNameMeta.touched == 0
    assert HostileReplayComparisonValue.touched == 0
    assert HostileKey.touched == 0
    expected = materialized["expected"]
    assert "<unreadable_HostileKey>" in expected
    assert expected["<unreadable_HostileKey>"]["value_type"] == "HostileReplayComparisonValue"


def test_stage1762_replay_comparison_source_removed_type_name_hook_paths() -> None:
    source = inspect.getsource(contracts)
    assert "no_hook_type_name" in source
    assert "type(value).__name__" not in source
