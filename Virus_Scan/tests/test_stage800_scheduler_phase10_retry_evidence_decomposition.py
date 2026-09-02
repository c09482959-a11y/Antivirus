from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.retry_callback_evidence import retry_policy_callback_evidence
from Virus_Scan.scheduler.queue.retry_evidence_support import retry_evidence_bool, retry_evidence_int, retry_evidence_text
from Virus_Scan.scheduler.queue.retry_integrity_evidence import retry_integrity_clear_evidence, retry_integrity_persistence_evidence
from Virus_Scan.scheduler.queue.retry_publication_evidence import retry_log_publication_evidence


def test_stage800_retry_evidence_is_split_into_owned_integrity_publication_callback_modules() -> None:
    integrity = retry_integrity_clear_evidence(path="sample.bin", attempt=2, error=OSError("clear failed"))
    persistence = retry_integrity_persistence_evidence(path="sample.bin", attempt=2, error=OSError("persist failed"))
    publication = retry_log_publication_evidence(
        path="sample.bin",
        attempt=2,
        error=OSError("publish failed"),
        original_error=ValueError("scan failed"),
    )
    callback = retry_policy_callback_evidence(path="sample.bin", attempt=2, callback_name="worker_once", error=RuntimeError("boom"))

    assert integrity.as_record()["stage"] == "queue_retry_integrity_clear"
    assert persistence.as_record()["stage"] == "queue_retry_integrity_persistence"
    assert publication.as_record()["stage"] == "queue_retry_log_publication"
    assert callback.as_record()["stage"] == "queue_retry_policy_callback"
    assert callback.as_scan_integrity()["queue_retry_policy_callback_failed"] is True


def test_stage800_dead_central_retry_policy_evidence_surface_is_removed() -> None:
    assert not Path("Virus_Scan/scheduler/queue/retry_policy_evidence.py").exists()


def test_stage1927_retry_policy_callback_missing_name_is_explicit_and_no_f_string_route():
    class HostileError(RuntimeError):
        def __str__(self):  # pragma: no cover - must not be invoked
            raise AssertionError("caller-owned __str__ executed")

    callback = retry_policy_callback_evidence(
        path="sample.bin",
        attempt=2,
        callback_name=None,
        error=HostileError("boom"),
    )
    record = callback.as_record()
    assert record["callback_name"] == "missing_retry_callback_name"
    assert record["error_source"] == "queue.retry_policy.missing_retry_callback_name"
    assert record["error_category"] == "HostileError"


def test_stage1927_retry_evidence_support_rejects_hostile_field_names_without_format_hooks():
    class HostileFieldName:
        touched = 0

        def __str__(self):  # pragma: no cover - must not be invoked
            type(self).touched += 1
            raise AssertionError("caller-owned __str__ executed")

        def __format__(self, _spec):  # pragma: no cover - must not be invoked
            type(self).touched += 1
            raise AssertionError("caller-owned __format__ executed")

    hostile_name = HostileFieldName()
    for func, value in (
        (retry_evidence_int, object()),
        (retry_evidence_text, object()),
        (retry_evidence_bool, object()),
    ):
        try:
            func(value, field_name=hostile_name)
        except ValueError as exc:
            assert "scheduler_retry_field_rejected" in str(exc)
        else:  # pragma: no cover - regression guard
            raise AssertionError("hostile retry evidence value accepted")
    assert HostileFieldName.touched == 0
