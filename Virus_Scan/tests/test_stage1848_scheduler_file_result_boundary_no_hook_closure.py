"""Stage 1848: scheduler file-result boundary no-hook closure."""
from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scheduler.execution.file_result_boundary import (
    execution_evidence_present,
    execution_float,
    execution_mapping,
    execution_path_text,
    execution_result_degraded,
    execution_sequence,
    execution_text,
)


class HostileFieldName:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("field_name __str__ must not be invoked")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("field_name __format__ must not be invoked")


class HostileNumeric:
    touched = 0

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("numeric __float__ must not be invoked")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("numeric __str__ must not be invoked")


class HostilePath:
    touched = 0

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("path __fspath__ must not be invoked")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("path __str__ must not be invoked")


class HostileEvidence:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("evidence __bool__ must not be invoked")

    def __len__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("evidence __len__ must not be invoked")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("evidence __str__ must not be invoked")


@pytest.mark.parametrize(
    ("callable_name", "expected"),
    (
        ("mapping", "scheduler_execution_field_mapping_rejected"),
        ("sequence", "scheduler_execution_field_sequence_rejected"),
        ("text", "scheduler_execution_field_text_missing"),
        ("float", "scheduler_execution_field_float_rejected"),
        ("path", "scheduler_execution_field_path_rejected:scheduler_path_rejected"),
    ),
)
def test_stage1848_hostile_field_names_are_rejected_without_hooks(callable_name: str, expected: str) -> None:
    HostileFieldName.touched = 0
    hostile_field = HostileFieldName()

    with pytest.raises(ValueError, match=expected):
        if callable_name == "mapping":
            execution_mapping(object(), field_name=hostile_field)  # type: ignore[arg-type]
        elif callable_name == "sequence":
            execution_sequence(object(), field_name=hostile_field)  # type: ignore[arg-type]
        elif callable_name == "text":
            execution_text("", field_name=hostile_field, allow_empty=False)  # type: ignore[arg-type]
        elif callable_name == "float":
            execution_float(HostileNumeric(), field_name=hostile_field)  # type: ignore[arg-type]
        else:
            execution_path_text(HostilePath(), field_name=hostile_field)  # type: ignore[arg-type]

    assert HostileFieldName.touched == 0


def test_stage1848_hostile_values_are_rejected_without_scalar_or_path_hooks() -> None:
    HostileNumeric.touched = 0
    HostilePath.touched = 0

    with pytest.raises(ValueError, match="scheduler_execution_duration_float_rejected"):
        execution_float(HostileNumeric(), field_name="duration")
    with pytest.raises(ValueError, match="scheduler_execution_file_path_path_rejected:scheduler_path_rejected"):
        execution_path_text(HostilePath(), field_name="file_path")

    assert HostileNumeric.touched == 0
    assert HostilePath.touched == 0


def test_stage1848_file_result_boundary_sources_close_fallback_and_fstring_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    boundary_source = (root / "scheduler/execution/file_result_boundary.py").read_text(encoding="utf-8")
    support_source = (root / "scheduler/execution/file_result_boundary_support.py").read_text(encoding="utf-8")
    combined_source = "\n".join((boundary_source, support_source))

    for forbidden in (
        'f"scheduler_execution_',
        'f"{reason',
        "fallback=",
        "scheduler_float",
        "raise ValueError(f",
        "optional_execution_mapping",
    ):
        assert forbidden not in combined_source

    assert "global_raw_snapshot: dict[object, object]" in (root / "scheduler/execution/scheduler_file_analysis.py").read_text(encoding="utf-8")
    assert "execution_boundary_reason" in boundary_source
    assert "execution_float_value" in boundary_source
    assert "no_hook_finite_float" in support_source
    assert "str.__add__(" in support_source

def test_stage1848_evidence_presence_uses_exact_builtin_containers_without_hooks() -> None:
    HostileEvidence.touched = 0
    hostile = HostileEvidence()

    assert execution_evidence_present(None) is False
    assert execution_evidence_present(False) is False
    assert execution_evidence_present(0) is False
    assert execution_evidence_present("") is False
    assert execution_evidence_present(()) is False
    assert execution_evidence_present({}) is False
    assert execution_evidence_present("error") is True
    assert execution_evidence_present(("error",)) is True
    assert execution_evidence_present(hostile) is True
    assert execution_result_degraded({"error": hostile}) is True
    assert HostileEvidence.touched == 0

def test_stage1848_absent_optional_yara_sequences_are_explicit_empty_without_hooks() -> None:
    assert execution_sequence(None, field_name="prefilter_yara_hits") == ()
    assert execution_sequence([], field_name="prefilter_yara_hits") == ()
    assert execution_sequence(["hit"], field_name="prefilter_yara_hits") == ("hit",)

