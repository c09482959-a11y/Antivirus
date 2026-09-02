from __future__ import annotations

import pytest

from Virus_Scan.scheduler.api.thread_lifecycle import SchedulerThreadPool
from Virus_Scan.scheduler.api import thread_lifecycle
from Virus_Scan.scheduler.contracts.contract_fields import (
    contract_mapping_items,
    contract_mapping_rejected,
)
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_items
from Virus_Scan.scheduler.evidence.execution_event_support import (
    first_text_mapping_value,
    immutable_execution_tuple,
    scheduler_bool_metadata_value,
)
from Virus_Scan.scheduler.evidence.partial_output_support import (
    partial_every_value,
    partial_force_value,
    partial_result_count,
    partial_timestamp_value,
    partial_total_files_value,
)


class HostileObject:
    def __getattribute__(self, name: str):  # pragma: no cover - must not be invoked
        raise AssertionError(f"hostile __getattribute__ invoked for {name}")

    def __bool__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("hostile __bool__ invoked")

    def __iter__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("hostile __iter__ invoked")

    def __len__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("hostile __len__ invoked")

    def __str__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("hostile __str__ invoked")


def _log_sink(messages: list[str]):
    def log_error(message: str) -> None:
        messages.append(message)

    return log_error


def test_stage2088_thread_lifecycle_sentinels_are_protocol_and_constructor_defaults() -> None:
    pool = SchedulerThreadPool(max_workers=1, thread_name_prefix=None, cancel_on_error="0")
    assert pool.thread_name_prefix == ""
    assert pool.cancel_on_error is False
    assert thread_lifecycle._exact_cancel_on_error(None) is True
    assert thread_lifecycle._exact_cancel_on_error(0) is False
    assert pool.__exit__(None, None, None) is False
    with pytest.raises(TypeError):
        thread_lifecycle._exact_thread_name_prefix(HostileObject())


def test_stage2088_contract_mapping_sentinels_reject_without_caller_hooks() -> None:
    hostile = HostileObject()
    assert contract_mapping_items(hostile) is None
    rejected = contract_mapping_rejected(hostile, field_name="payload")
    assert len(rejected) == 1
    assert rejected[0]["scheduler_contract_field_rejected"] is True
    assert rejected[0]["reason"] == "scheduler_contract_mapping_rejected"
    assert contract_mapping_rejected(None, field_name="payload") == ()


def test_stage2088_evidence_record_mapping_sentinel_rejects_without_caller_hooks() -> None:
    assert scheduler_mapping_items(HostileObject()) is None


def test_stage2088_execution_event_sentinels_are_absence_or_typed_evidence() -> None:
    hostile = HostileObject()
    assert scheduler_bool_metadata_value(None, field_name="fatal") is False
    assert scheduler_bool_metadata_value("", field_name="fatal") is False
    rejected_bool = scheduler_bool_metadata_value(hostile, field_name="fatal")
    assert rejected_bool["unsupported_scheduler_value"] is True
    assert immutable_execution_tuple(None) == ()
    rejected_tuple = immutable_execution_tuple(hostile)
    assert len(rejected_tuple) == 1
    assert rejected_tuple[0]["unsupported_scheduler_value"] is True
    assert first_text_mapping_value(None, "path") is None
    assert first_text_mapping_value((("path", "sample.bin"),), "path") == "sample.bin"


def test_stage2088_partial_output_sentinels_log_rejection_or_represent_absence() -> None:
    messages: list[str] = []
    log_error = _log_sink(messages)
    hostile = HostileObject()

    assert partial_result_count(hostile, context="stage2088", log_error=log_error) is None
    assert partial_every_value(None, context="stage2088", log_error=log_error) == 0
    assert partial_every_value(hostile, context="stage2088", log_error=log_error) == 0
    assert partial_total_files_value(None, context="stage2088", log_error=log_error) == 0
    assert partial_total_files_value(hostile, context="stage2088", log_error=log_error) == 0
    assert partial_timestamp_value(None, context="stage2088", field="elapsed", log_error=log_error) == 0.0
    assert partial_timestamp_value(hostile, context="stage2088", field="elapsed", log_error=log_error) == 0.0
    assert partial_force_value(None, context="stage2088", log_error=log_error) is False
    assert partial_force_value(hostile, context="stage2088", log_error=log_error) is False

    assert any("results rejected" in message for message in messages)
    assert any("partial_output_every rejected" in message for message in messages)
    assert any("total_files rejected" in message for message in messages)
    assert any("elapsed rejected" in message for message in messages)
    assert any("force rejected" in message for message in messages)
