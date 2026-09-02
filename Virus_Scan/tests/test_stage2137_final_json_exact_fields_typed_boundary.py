from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    collect_exact_scheduler_evidence,
    exact_contains_fragment,
    exact_flag,
    exact_has_content,
    exact_int_with_rejection,
    exact_mapping_items,
    exact_mapping_value,
    exact_text,
    first_exact_text,
    is_exact_mapping,
)


class HostileAttributeObject:
    touched = 0

    def __getattribute__(self, name):  # pragma: no cover - failure proves unsafe probing
        type(self).touched += 1
        raise AssertionError(f"caller-owned attribute hook invoked for {name}")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned string conversion invoked")


class HostileBoolObject:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned bool conversion invoked")


def test_stage2137_final_json_exact_fields_has_no_local_dynamic_typing_surface() -> None:
    source = Path("Virus_Scan/scheduler/evidence/final_json_exact_fields.py").read_text()

    assert "typing import" in source
    assert "object | None" in source
    assert "Any" not in source
    assert "ExactMappingItems" in source


def test_stage2137_exact_mapping_helpers_preserve_dict_and_proxy_values() -> None:
    data = {"status": "failed", "attempt": "7", "nested": {"reason": "timeout"}}
    proxy = MappingProxyType(data)

    assert is_exact_mapping(data) is True
    assert is_exact_mapping(proxy) is True
    assert list(exact_mapping_items(data)) == [("status", "failed"), ("attempt", "7"), ("nested", {"reason": "timeout"})]
    assert exact_mapping_value(proxy, "status") == "failed"
    assert first_exact_text(proxy, "missing", "status") == "failed"
    assert exact_flag(proxy, "status") is True
    assert exact_int_with_rejection(proxy, "attempt") == (7, False)
    assert exact_contains_fragment(proxy, "time") is True
    assert exact_has_content(proxy) is True


def test_stage2137_exact_scalar_helpers_reject_hostile_objects_without_hooks() -> None:
    HostileAttributeObject.touched = 0
    HostileBoolObject.touched = 0
    hostile = HostileAttributeObject()
    hostile_bool = HostileBoolObject()

    assert exact_mapping_items(hostile) is None
    assert exact_text(hostile) is None
    assert exact_has_content(hostile_bool) is False
    assert exact_contains_fragment(hostile, "x") is False
    assert HostileAttributeObject.touched == 0
    assert HostileBoolObject.touched == 0


def test_stage2137_collect_exact_scheduler_evidence_keeps_exact_records_only() -> None:
    record = SchedulerEvidenceRecord(
        stage="scheduler",
        state="failure",
        error_category="timeout",
        error_source="scheduler.timeout",
        message="timed out",
        fatal=True,
    )

    collected = collect_exact_scheduler_evidence((record, HostileAttributeObject(), {"stage": "queue"}))

    assert record in collected
    assert all(type(item) is SchedulerEvidenceRecord for item in collected)
