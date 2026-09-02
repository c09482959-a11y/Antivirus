from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.internal import scheduler_config_values
from Virus_Scan.scheduler.internal.scheduler_config_values import (
    _config_float,
    _config_int,
    process_queue_env_float,
    process_queue_env_int,
)


class HostileFieldName(str):
    touched = False

    def __str__(self):  # pragma: no cover - must not execute
        HostileFieldName.touched = True
        raise AssertionError("str hook executed")

    def __format__(self, _spec):  # pragma: no cover - must not execute
        HostileFieldName.touched = True
        raise AssertionError("format hook executed")


class HostileScalar:
    touched = False

    def __float__(self):  # pragma: no cover - must not execute
        HostileScalar.touched = True
        raise AssertionError("float hook executed")

    def __int__(self):  # pragma: no cover - must not execute
        HostileScalar.touched = True
        raise AssertionError("int hook executed")

    def __str__(self):  # pragma: no cover - must not execute
        HostileScalar.touched = True
        raise AssertionError("str hook executed")


def _recorder():
    calls = []

    def record(stage, exc, *, extra=None):
        calls.append((stage, exc, extra))

    return calls, record


def test_config_helpers_reject_hostile_field_without_formatting_reason_prefix() -> None:
    calls, record = _recorder()
    HostileFieldName.touched = False
    HostileScalar.touched = False
    field = HostileFieldName("worker_count")
    assert _config_float(HostileScalar(), default=2.5, record_suppressed=record, stage="stage", field=field) == 2.5
    assert _config_int(HostileScalar(), default=3, record_suppressed=record, stage="stage", field=field) == 3
    assert [str(call[1]) for call in calls] == ["scheduler_config_rejected", "scheduler_config_rejected"]
    assert HostileFieldName.touched is False
    assert HostileScalar.touched is False


def test_process_queue_env_config_preserves_exact_default_and_env_values() -> None:
    calls, record = _recorder()
    env = {"FLOAT_VALUE": "7.5", "INT_VALUE": "11"}
    assert process_queue_env_float("FLOAT_VALUE", 2.0, minimum=1.0, record_suppressed=record, env_get=env.get) == 7.5
    assert process_queue_env_int("INT_VALUE", 2, minimum=1, record_suppressed=record, env_get=env.get) == 11
    assert calls == []


def test_process_queue_env_config_records_rejection_with_owned_reason_text() -> None:
    calls, record = _recorder()
    env = {"FLOAT_VALUE": HostileScalar(), "INT_VALUE": HostileScalar()}
    assert process_queue_env_float("FLOAT_VALUE", 2.0, minimum=1.0, record_suppressed=record, env_get=env.get) == 2.0
    assert process_queue_env_int("INT_VALUE", 2, minimum=1, record_suppressed=record, env_get=env.get) == 2
    assert [str(call[1]) for call in calls] == ["FLOAT_VALUE_rejected", "INT_VALUE_rejected"]


def test_scheduler_config_values_has_no_fallback_route_or_field_fstring() -> None:
    source = Path(scheduler_config_values.__file__).read_text(encoding="utf-8")
    assert "fallback" not in source
    assert 'f"{field}_' not in source
    tree = ast.parse(source)
    assert not any(isinstance(node, ast.FormattedValue) for node in ast.walk(tree))
