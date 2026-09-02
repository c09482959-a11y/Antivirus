from __future__ import annotations

from types import MappingProxyType

import pytest

from Virus_Scan.scheduler.api.contracts import HybridQueueStateError
from Virus_Scan.scheduler.replay.replay_projection_failure import build_replay_projection_failure_result
from Virus_Scan.scheduler.replay.replay_result_fields import replay_mapping_value
from Virus_Scan.scheduler.replay.replay_snapshot import validate_hybrid_counts


class HostileHookValue:
    touched: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.touched = []

    def __str__(self):  # pragma: no cover - failure path
        type(self).touched.append("str")
        raise AssertionError("__str__ must not be called")

    def __repr__(self):  # pragma: no cover - failure path
        type(self).touched.append("repr")
        raise AssertionError("__repr__ must not be called")

    def __bool__(self):  # pragma: no cover - failure path
        type(self).touched.append("bool")
        raise AssertionError("__bool__ must not be called")

    def __int__(self):  # pragma: no cover - failure path
        type(self).touched.append("int")
        raise AssertionError("__int__ must not be called")

    def __float__(self):  # pragma: no cover - failure path
        type(self).touched.append("float")
        raise AssertionError("__float__ must not be called")

    def __iter__(self):  # pragma: no cover - failure path
        type(self).touched.append("iter")
        raise AssertionError("__iter__ must not be called")


class HostileDict(dict):
    touched: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.touched = []

    def items(self):  # pragma: no cover - failure path
        type(self).touched.append("items")
        raise AssertionError("items must not be called")

    def keys(self):  # pragma: no cover - failure path
        type(self).touched.append("keys")
        raise AssertionError("keys must not be called")

    def values(self):  # pragma: no cover - failure path
        type(self).touched.append("values")
        raise AssertionError("values must not be called")

    def __iter__(self):  # pragma: no cover - failure path
        type(self).touched.append("iter")
        raise AssertionError("__iter__ must not be called")

    def __getitem__(self, key):  # pragma: no cover - failure path
        type(self).touched.append("getitem")
        raise AssertionError("__getitem__ must not be called")


class HostileException(RuntimeError):
    touched: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.touched = []

    def __str__(self):  # pragma: no cover - failure path
        type(self).touched.append("str")
        raise AssertionError("exception __str__ must not be called")

    def __repr__(self):  # pragma: no cover - failure path
        type(self).touched.append("repr")
        raise AssertionError("exception __repr__ must not be called")


def test_stage1574_replay_mapping_proxy_backed_by_hostile_dict_is_rejected_without_hooks() -> None:
    HostileDict.reset()
    result = MappingProxyType(HostileDict({"job_id": "job-1574"}))

    with pytest.raises(RuntimeError, match="malformed scheduler replay result record"):
        replay_mapping_value(result, "job_id")

    assert HostileDict.touched == []


def test_stage1574_replay_projection_failure_does_not_iterate_or_repr_raw_results() -> None:
    HostileHookValue.reset()
    HostileException.reset()
    comparison = build_replay_projection_failure_result(
        "actual",
        HostileException("boom"),
        HostileHookValue(),
    )

    assert comparison.matched is False
    assert comparison.actual.evidence[0]["error_category"] == "replay_projection_failure"
    assert comparison.actual.records[0]["unavailable_reason"] == "non_materializable_scheduler_replay_projection_raw_record_value"
    assert HostileHookValue.touched == []
    assert HostileException.touched == []


def test_stage1574_validate_hybrid_counts_rejects_unknown_mapping_without_hooks() -> None:
    HostileDict.reset()

    with pytest.raises(HybridQueueStateError, match="invalid hybrid queue count mapping"):
        validate_hybrid_counts(HostileDict({"active": 1}))

    assert HostileDict.touched == []


def test_stage1574_validate_hybrid_counts_rejects_hostile_key_and_value_without_hooks() -> None:
    HostileHookValue.reset()

    with pytest.raises(HybridQueueStateError):
        validate_hybrid_counts({HostileHookValue(): HostileHookValue()})

    assert HostileHookValue.touched == []


def test_stage1574_validate_hybrid_counts_preserves_exact_builtin_counts() -> None:
    counts = validate_hybrid_counts({"active": "2", "done": 1, "failed": 0.0})

    assert dict(counts) == {"active": 2, "done": 1, "failed": 0}
