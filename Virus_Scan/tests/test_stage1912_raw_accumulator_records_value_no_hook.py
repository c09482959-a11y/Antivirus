from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.queue.raw_accumulator_records import (
    empty_raw_accumulator,
    initialized_record,
    reconciled_expected_record,
)
from Virus_Scan.scheduler.queue.raw_accumulator_store import raw_accumulator_dependencies
from Virus_Scan.scheduler.queue.raw_accumulator_value_support import coerce_nonnegative_int, raw_mapping, raw_text


class HostileRawAccumulatorValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - touching proves unsafe route
        type(self).touched += 1
        raise AssertionError("raw accumulator called __bool__")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator called __iter__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator called __format__")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator called __int__")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator called __float__")

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw accumulator called __fspath__")


class HostileTextKey:
    touched = 0

    def __hash__(self):
        return 1912

    def __eq__(self, other):
        return self is other

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw mapping called key __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw mapping called key __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw mapping called key __format__")


def _reset() -> None:
    HostileRawAccumulatorValue.touched = 0
    HostileTextKey.touched = 0


def test_stage1912_raw_text_rejects_unknown_values_without_fallback_or_hooks() -> None:
    _reset()
    value = HostileRawAccumulatorValue()

    assert raw_text(value, field_name="raw_accumulator_file_id") == (
        "<raw_accumulator_file_id unsafe_raw_accumulator_file_id_rejected>"
    )
    assert empty_raw_accumulator(value)["file_id"] == (
        "<raw_accumulator_file_id unsafe_raw_accumulator_file_id_rejected>"
    )
    assert HostileRawAccumulatorValue.touched == 0


def test_stage1912_initialized_record_rejects_identity_keys_and_stage_text_without_hooks(tmp_path: Path) -> None:
    _reset()
    deps = raw_accumulator_dependencies()
    key = HostileTextKey()
    value = HostileRawAccumulatorValue()

    record = initialized_record(
        tmp_path / "sample.bin",
        value,
        expected=1,
        initial_tags=[],
        effective_stage=value,
        ext_stage=value,
        identity={key: value},
        deps=deps,
    )

    assert record["file_id"] == "<raw_accumulator_file_id unsafe_raw_accumulator_file_id_rejected>"
    assert record["file"].endswith("/sample.bin")
    assert record["effective_stage"] == (
        "<raw_accumulator_effective_stage unsafe_raw_accumulator_effective_stage_rejected>"
    )
    assert record["ext_stage"] == "<raw_accumulator_ext_stage unsafe_raw_accumulator_ext_stage_rejected>"
    assert "unsupported_raw_accumulator_identity_key_0" in record["identity"]
    assert HostileRawAccumulatorValue.touched == 0
    assert HostileTextKey.touched == 0


def test_stage1912_reconcile_expected_builds_error_without_reason_format_hooks() -> None:
    _reset()
    deps = raw_accumulator_dependencies()
    value = HostileRawAccumulatorValue()
    record = {"expected": 2, "completed": 2, "failed": 0, "retried": 0, "tags": [], "errors": []}

    updated = reconciled_expected_record(record, 4, reason=value, deps=deps)

    expected_reason = "<raw_accumulator_reconcile_reason unsafe_raw_accumulator_reconcile_reason_rejected>"
    assert updated["expected"] == 4
    assert updated["raw_failures"][-1]["error"] == expected_reason + ": expected 2 -> 4"
    assert updated["errors"][-1] == expected_reason + ": expected 2 -> 4"
    assert HostileRawAccumulatorValue.touched == 0


def test_stage1912_numeric_default_rejects_hostile_value_and_hostile_default_without_hooks() -> None:
    _reset()
    value = HostileRawAccumulatorValue()
    default = HostileRawAccumulatorValue()

    assert coerce_nonnegative_int(value, 7) == 7
    assert coerce_nonnegative_int(value, default) == 0
    assert HostileRawAccumulatorValue.touched == 0


def test_stage1912_raw_mapping_materializes_non_text_keys_without_key_string_hooks() -> None:
    _reset()
    key = HostileTextKey()
    mapped = raw_mapping({key: "safe"}, field_name="raw_accumulator_identity")

    assert mapped == {"unsupported_raw_accumulator_identity_key_0": "safe"}
    assert HostileTextKey.touched == 0


def test_stage1912_raw_accumulator_value_source_guards() -> None:
    records_source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_accumulator_records.py"))
    support_source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_accumulator_value_support.py"))

    assert "raw_text(file_id, fallback=" not in records_source
    assert "raw_text(path, fallback=" not in records_source
    assert "fallback=\"unknown\"" not in records_source
    assert "raw_text(reason, fallback=" not in records_source
    assert "f\"{reason_text}: expected" not in records_source
    assert "def raw_text(value: Any, *, fallback" not in support_source
    assert "return fallback" not in support_source
    assert "_fallback_reason" not in support_source
    assert 'f"missing_{field_name}"' not in support_source
    assert 'f"unsafe_{field_name}_rejected"' not in support_source
    assert 'f"unsupported_{field_name}_key_{index}"' not in support_source
