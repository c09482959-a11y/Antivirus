from __future__ import annotations

from pathlib import Path

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.runtime import env_policy
from Virus_Scan.scheduler.runtime.env_policy import bool_env, float_env, int_env


class HostileScalar:
    touched: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.touched = []

    def __bool__(self):  # pragma: no cover - failure path
        type(self).touched.append("bool")
        raise AssertionError("__bool__ must not be called")

    def __int__(self):  # pragma: no cover - failure path
        type(self).touched.append("int")
        raise AssertionError("__int__ must not be called")

    def __float__(self):  # pragma: no cover - failure path
        type(self).touched.append("float")
        raise AssertionError("__float__ must not be called")

    def __format__(self, spec):  # pragma: no cover - failure path
        type(self).touched.append("format")
        raise AssertionError("__format__ must not be called")

    def __str__(self):  # pragma: no cover - failure path
        type(self).touched.append("str")
        raise AssertionError("__str__ must not be called")

    def __repr__(self):  # pragma: no cover - failure path
        type(self).touched.append("repr")
        raise AssertionError("__repr__ must not be called")


class HostileMapping(dict):
    touched: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.touched = []

    def __iter__(self):  # pragma: no cover - failure path
        type(self).touched.append("iter")
        raise AssertionError("mapping iteration must not be called")

    def __getitem__(self, key):  # pragma: no cover - failure path
        type(self).touched.append("getitem")
        raise AssertionError("mapping item access must not be called")

    def get(self, key, default=None):  # pragma: no cover - failure path
        type(self).touched.append("get")
        raise AssertionError("mapping get must not be called")

    def items(self):  # pragma: no cover - failure path
        type(self).touched.append("items")
        raise AssertionError("mapping items must not be called")


def _reset() -> None:
    HostileScalar.reset()
    HostileMapping.reset()
    clear_failure_records()


def test_stage1934_env_policy_rejects_hostile_defaults_and_names_without_hooks() -> None:
    _reset()
    hostile = HostileScalar()

    assert float_env({}, hostile, hostile, (Exception,)) == 0.0
    assert int_env({}, hostile, hostile, (Exception,)) == 0
    assert bool_env({}, hostile, hostile, (Exception,)) is False

    assert HostileScalar.touched == []
    where = tuple(record["where"] for record in failure_snapshot()["records"])
    assert "scheduler_env_float_default_rejected" in where
    assert "scheduler_env_integer_default_rejected" in where
    assert "scheduler_env_bool_default_rejected" in where


def test_stage1934_env_policy_rejects_hostile_mapping_values_without_hooks() -> None:
    _reset()
    mapping = HostileMapping({"VALUE": HostileScalar()})

    assert float_env(mapping, "VALUE", 2.5, (Exception,)) == 2.5
    assert int_env(mapping, "VALUE", 7, (Exception,)) == 7
    assert bool_env(mapping, "VALUE", True, (Exception,)) is True

    assert HostileMapping.touched == []
    assert HostileScalar.touched == []
    where = tuple(record["where"] for record in failure_snapshot()["records"])
    assert "scheduler_env_float_rejected" in where
    assert "scheduler_env_integer_rejected" in where
    assert "scheduler_env_bool_rejected" in where


def test_stage1934_env_policy_source_closes_fallback_and_fstring_rows() -> None:
    source = Path(env_policy.__file__).read_text(encoding="utf-8")
    forbidden = (
        "fallback: Any,",
        'f"scheduler_env_{parser}_rejected"',
        'field_name=f"{setting}_fallback"',
        '"fallback": scheduler_value_snapshot',
        "fallback, fallback_reason =",
        "if fallback_reason:",
        "fallback=0.0,",
        "fallback=0,",
        "fallback=False,",
        "fallback=fallback,",
        "_snapshot_env_value(env, name, fallback)",
        "return fallback",
    )
    for snippet in forbidden:
        assert snippet not in source
