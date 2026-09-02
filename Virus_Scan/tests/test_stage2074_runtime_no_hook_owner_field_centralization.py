"""Stage2074 runtime no-hook owner-field centralization regressions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_owner_field,
    no_hook_exact_owner_field_status,
)


@dataclass
class _OwnedRecord:
    value: str


class _HostileRecord:
    touched = 0

    def __getattribute__(self, name: str) -> Any:  # pragma: no cover - fails if invoked
        type(self).touched += 1
        raise RuntimeError("hostile getattribute invoked")


def test_stage2074_exact_owner_field_reads_owned_dataclass_without_custom_hooks() -> None:
    record = _OwnedRecord("safe")

    value, reason = no_hook_exact_owner_field_status(record, _OwnedRecord, "value")

    assert value == "safe"
    assert reason == ""
    assert no_hook_exact_owner_field(record, _OwnedRecord, "value") == "safe"


def test_stage2074_exact_owner_field_rejects_hostile_owner_without_invoking_hook() -> None:
    _HostileRecord.touched = 0

    value, reason = no_hook_exact_owner_field_status(_HostileRecord(), _HostileRecord, "value")

    assert value is None
    assert reason == "custom_getattribute"
    assert _HostileRecord.touched == 0


def test_stage2074_runtime_sources_have_no_local_direct_object_getattribute_reads() -> None:
    runtime_root = Path("Virus_Scan/runtime")
    offenders = sorted(
        str(path)
        for path in runtime_root.glob("*.py")
        if "object.__getattribute__" in path.read_text(encoding="utf-8")
    )

    assert offenders == []
