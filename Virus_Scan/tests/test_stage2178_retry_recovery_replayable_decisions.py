from __future__ import annotations

import pytest

from Virus_Scan.scheduler.queue.retry_evidence_support import (
    retry_evidence_optional_int,
    retry_history_snapshot,
)
from Virus_Scan.scheduler.queue.retry_integrity_access import safe_get_integrity
from Virus_Scan.scheduler.queue.retry_recovery_decisions import (
    retry_history_decision,
    retry_integrity_mapping_decision,
    retry_integrity_missing_decision,
    retry_optional_int_decision,
    scheduler_recovery_record_decision,
    scheduler_recovery_text_decision,
)


class HostileValue:
    touched = 0

    def __str__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")

    def __repr__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ executed")

    def __iter__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __iter__ executed")

    def items(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("caller-owned items executed")

    def __bool__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ executed")


def test_stage2178_recovery_record_and_text_decisions_are_replayable_without_hooks() -> None:
    HostileValue.touched = 0
    hostile = HostileValue()

    record = scheduler_recovery_record_decision(hostile)
    text = scheduler_recovery_text_decision(hostile)

    assert record.accepted is False
    assert record.reason == "scheduler_recovery_record_unavailable"
    assert record.as_mapping() == {}
    assert text.accepted is False
    assert text.reason == "scheduler_recovery_text_rejected"
    assert text.as_text() == ""
    assert HostileValue.touched == 0


def test_stage2178_retry_optional_int_decision_preserves_missing_and_rejection_paths() -> None:
    HostileValue.touched = 0
    missing = retry_optional_int_decision(None, field_name=HostileValue())
    rejected = retry_optional_int_decision(HostileValue(), field_name="attempt")
    accepted = retry_optional_int_decision(3, field_name="attempt")

    assert missing.reason == "scheduler_retry_field_missing_optional_int"
    assert missing.as_optional_int() is None
    assert rejected.reason == "scheduler_retry_attempt_rejected"
    with pytest.raises(ValueError, match="scheduler_retry_attempt_rejected"):
        retry_evidence_optional_int(HostileValue(), field_name="attempt")
    assert accepted.as_optional_int() == 3
    assert HostileValue.touched == 0


def test_stage2178_retry_history_decision_records_missing_and_rejected_paths_without_hooks() -> None:
    HostileValue.touched = 0
    missing = retry_history_decision(None)
    rejected = retry_history_decision(HostileValue())

    assert missing.reason == "retry_history_missing"
    assert missing.as_history() == ()
    assert retry_history_snapshot(None) == ()
    assert rejected.reason == "retry_history_rejected"
    assert rejected.as_history()[0]["action"] == "retry_history_rejected"
    assert rejected.as_history()[0]["replay_must_reproduce"] is True
    assert HostileValue.touched == 0


def test_stage2178_retry_integrity_decisions_preserve_canonical_shapes_without_hooks() -> None:
    HostileValue.touched = 0
    unsupported = retry_integrity_mapping_decision(HostileValue())
    missing = retry_integrity_missing_decision(None)
    failures: list[dict[str, object]] = []

    assert unsupported.accepted is False
    assert unsupported.reason == "retry_integrity_mapping_rejected"
    assert unsupported.as_optional_mapping() is None
    assert missing.reason == "retry_integrity_missing"
    assert missing.as_integrity() == {}
    assert safe_get_integrity(
        get_integrity=lambda _path: None,
        path="sample.bin",
        attempt=1,
        retry_failures=failures,
    ) == {}
    assert failures == []
    assert HostileValue.touched == 0
