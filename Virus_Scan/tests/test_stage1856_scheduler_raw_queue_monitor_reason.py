from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.internal import raw_queue_monitor_no_hook
from Virus_Scan.scheduler.internal.raw_queue_monitor_no_hook import plain_scheduler_mapping


class HostileFieldName(str):
    touched = False

    def __str__(self):  # pragma: no cover - must not execute
        HostileFieldName.touched = True
        raise AssertionError("str hook executed")

    def __format__(self, _spec):  # pragma: no cover - must not execute
        HostileFieldName.touched = True
        raise AssertionError("format hook executed")


class HostileMapping:
    def items(self):  # pragma: no cover - must not execute
        raise AssertionError("items hook executed")


def test_plain_scheduler_mapping_reason_uses_owned_exact_field_name() -> None:
    evidence = plain_scheduler_mapping(HostileMapping(), field_name="raw_queue")
    assert evidence["pressure"] is False
    assert evidence["reason"] == "unsupported_raw_queue"
    assert evidence["evidence"]["unsupported_scheduler_value"] is True


def test_plain_scheduler_mapping_rejects_hostile_field_name_without_formatting() -> None:
    HostileFieldName.touched = False
    evidence = plain_scheduler_mapping(HostileMapping(), field_name=HostileFieldName("raw_queue"))  # type: ignore[arg-type]
    assert evidence["pressure"] is False
    assert evidence["reason"] == "unsupported_scheduler_mapping"
    assert HostileFieldName.touched is False


def test_raw_queue_monitor_no_hook_has_no_field_name_fstring_reason() -> None:
    source = Path(raw_queue_monitor_no_hook.__file__).read_text(encoding="utf-8")
    assert 'f"unsupported_{field_name}"' not in source
    tree = ast.parse(source)
    assert not any(isinstance(node, ast.FormattedValue) for node in ast.walk(tree))
