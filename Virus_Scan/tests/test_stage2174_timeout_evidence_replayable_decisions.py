from __future__ import annotations

import pytest

from Virus_Scan.scheduler.queue.inmemory_recovery_evidence_journal import (
    InMemoryRecoveryEvidenceJournal,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_config_values import (
    MinimumConfigEvidenceRequest,
    minimum_config_evidence_decision,
    record_minimum_if_needed,
)


class _HostileFloat:
    def __float__(self):  # pragma: no cover - proves hook avoidance
        raise AssertionError("float hook executed")

    def __str__(self):  # pragma: no cover
        raise AssertionError("str hook executed")

    def __repr__(self):  # pragma: no cover
        raise AssertionError("repr hook executed")


class _HostileEvidenceRecord:
    touched = False

    def __iter__(self):  # pragma: no cover
        type(self).touched = True
        raise AssertionError("iter hook executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched = True
        raise AssertionError("repr hook executed")


def test_stage2174_timeout_config_minimum_clean_path_is_replayable_decision() -> None:
    decision = minimum_config_evidence_decision(
        MinimumConfigEvidenceRequest(
            evidence=(),
            setting="UMIGE_INMEMORY_PROGRESS_STALE_SEC",
            raw_value="240",
            parsed_value=240.0,
            minimum_value=120.0,
            default_value=240.0,
        )
    )

    assert decision.accepted is True
    assert decision.reason == "timeout_config_minimum_within_bounds"
    assert decision.as_evidence() == ()
    assert record_minimum_if_needed(
        MinimumConfigEvidenceRequest(
            evidence=(),
            setting="UMIGE_INMEMORY_PROGRESS_STALE_SEC",
            raw_value="240",
            parsed_value=240.0,
            minimum_value=120.0,
            default_value=240.0,
        )
    ) == ()


def test_stage2174_timeout_config_minimum_rejects_hostile_values_as_decision() -> None:
    hostile = _HostileFloat()
    decision = minimum_config_evidence_decision(
        MinimumConfigEvidenceRequest(
            evidence=(),
            setting="UMIGE_INMEMORY_PROGRESS_STALE_SEC",
            raw_value=hostile,
            parsed_value=hostile,  # type: ignore[arg-type]
            minimum_value=120.0,
            default_value=240.0,
        )
    )

    assert decision.accepted is False
    assert decision.reason == "timeout_config_minimum_unavailable"
    assert decision.as_evidence() == ()


def test_stage2174_recovery_journal_empty_cursor_is_constant_semantics() -> None:
    journal = InMemoryRecoveryEvidenceJournal()

    assert journal.retry_count() == 0
    assert journal.retry_since(0) == ()
    assert journal.cancel_count() == 0
    assert journal.cancel_since(0) == ()


def test_stage2174_recovery_journal_rejects_invalid_cursors_fail_closed() -> None:
    journal = InMemoryRecoveryEvidenceJournal()
    journal.append_retry(({"stage": "retry"},))

    with pytest.raises(TypeError, match="retry_evidence_cursor_must_be_int"):
        journal.retry_since(True)
    with pytest.raises(ValueError, match="retry_evidence_cursor_negative"):
        journal.retry_since(-1)
    with pytest.raises(ValueError, match="retry_evidence_cursor_ahead_of_journal"):
        journal.retry_since(2)


def test_stage2174_recovery_journal_rejects_hostile_record_without_hooks() -> None:
    _HostileEvidenceRecord.touched = False
    journal = InMemoryRecoveryEvidenceJournal()
    journal.append_retry((_HostileEvidenceRecord(),))

    record = journal.retry_snapshot()[0]
    assert record["reason"] == "recovery_evidence_record_rejected"
    assert record["field_name"] == "retry_recovery_evidence[0]"
    assert _HostileEvidenceRecord.touched is False
