from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.internal.evidence_projection import (
    scheduler_evidence_path,
    scheduler_evidence_text,
)
from Virus_Scan.scheduler.internal.exception_projection import (
    scheduler_error_detail,
    scheduler_exception_text,
)


class HostileEvidenceValue:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection called __str__")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection called __repr__")

    def __format__(self, _spec):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection called __format__")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection called __bool__")

    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection called __iter__")

    def __fspath__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection called __fspath__")


class HostileFieldName:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection stringified field name")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection repr'd field name")

    def __format__(self, _spec):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection formatted field name")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection truth-tested field name")


class HostileMissingText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection stringified missing text")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection repr'd missing text")

    def __format__(self, _spec):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection formatted missing text")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("scheduler evidence projection truth-tested missing text")


def test_stage1853_scheduler_evidence_text_rejects_hostile_values_without_hooks() -> None:
    hostile = HostileEvidenceValue()
    hostile_field = HostileFieldName()
    HostileEvidenceValue.touched = 0
    HostileFieldName.touched = 0

    projected = scheduler_evidence_text(
        hostile,
        missing_text="retry_reason_missing",
        field_name=hostile_field,  # type: ignore[arg-type]
    )

    assert HostileEvidenceValue.touched == 0
    assert HostileFieldName.touched == 0
    assert projected == "<HostileEvidenceValue unsupported_scheduler_text>"


def test_stage1853_scheduler_evidence_text_uses_owned_missing_text_without_fallback() -> None:
    hostile_missing = HostileMissingText()
    HostileMissingText.touched = 0

    projected = scheduler_evidence_text(
        None,
        missing_text=hostile_missing,  # type: ignore[arg-type]
        field_name="retry_reason",
    )

    assert HostileMissingText.touched == 0
    assert projected == "scheduler_text_missing"


def test_stage1853_scheduler_evidence_path_rejects_hostile_values_without_hooks() -> None:
    hostile = HostileEvidenceValue()
    hostile_field = HostileFieldName()
    HostileEvidenceValue.touched = 0
    HostileFieldName.touched = 0

    projected = scheduler_evidence_path(hostile, field_name=hostile_field)  # type: ignore[arg-type]

    assert HostileEvidenceValue.touched == 0
    assert HostileFieldName.touched == 0
    assert projected == "<HostileEvidenceValue unsupported_scheduler_path>"


def test_stage1853_scheduler_evidence_projection_source_removes_fallback_and_fstrings() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/internal/evidence_projection.py"))

    assert "fallback:" not in source
    assert "fallback=" not in source
    assert "return text or fallback" not in source
    assert "return fallback" not in source
    assert 'unsupported_reason=f"unsupported_{field_name}"' not in source
    assert 'return f"<{no_hook_type_name(value)} {reason}>"' not in source
    assert 'return f"<{no_hook_type_name(value)} unsupported_{field_name}>"' not in source


class HostileSchedulerException(Exception):
    def __str__(self):
        HostileEvidenceValue.touched += 1
        raise AssertionError("scheduler exception projection called __str__")

    def __repr__(self):
        HostileEvidenceValue.touched += 1
        raise AssertionError("scheduler exception projection called __repr__")

    def __format__(self, _spec):
        HostileEvidenceValue.touched += 1
        raise AssertionError("scheduler exception projection called __format__")


class HostileExceptionArg:
    def __str__(self):
        HostileEvidenceValue.touched += 1
        raise AssertionError("scheduler exception projection stringified arg")

    def __repr__(self):
        HostileEvidenceValue.touched += 1
        raise AssertionError("scheduler exception projection repr'd arg")

    def __format__(self, _spec):
        HostileEvidenceValue.touched += 1
        raise AssertionError("scheduler exception projection formatted arg")


def test_stage1853_scheduler_exception_projection_rejects_hostile_exception_without_hooks() -> None:
    HostileEvidenceValue.touched = 0
    error = HostileSchedulerException(HostileExceptionArg())

    text = scheduler_exception_text(error)
    detail = scheduler_error_detail(error)

    assert HostileEvidenceValue.touched == 0
    assert text == "HostileSchedulerException: scheduler diagnostic detail unavailable without caller hooks"
    assert detail == text


def test_stage1853_scheduler_exception_projection_source_removes_fallback_fstrings_and_false_sentinels() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/internal/exception_projection.py"))

    assert "fallback:" not in source
    assert "fallback=" not in source
    assert "return False" not in source
    assert 'message.startswith(f"{type_name}:")' not in source
    assert 'return f"{type_name}: {message}"' not in source
    assert 'f"{type_name}: scheduler diagnostic detail unavailable without caller hooks"' not in source
