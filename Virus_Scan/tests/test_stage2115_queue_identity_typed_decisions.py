from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.queue.identity import (
    invalidate_identity_index,
    invalidate_identity_index_decision,
    queue_is_job_json_name,
    queue_is_job_json_name_decision,
)
from Virus_Scan.scheduler.queue.identity_decisions import (
    IdentityIndexInvalidationDecision,
    QueueJobNameDecision,
)


class BadQueueName:
    def __str__(self) -> str:
        raise ValueError("bad queue name")


class UntrustedQueueDir:
    def __bool__(self) -> bool:
        raise RuntimeError("truthiness must not be consulted")

    def __fspath__(self) -> str:
        raise TypeError("path normalization failed")


def _failure_wheres() -> set[str]:
    return {str(record.get("where")) for record in failure_snapshot().get("records", [])}


def test_stage2115_queue_job_name_decision_separates_rejections_from_valid_false() -> None:
    clear_failure_records()

    missing = queue_is_job_json_name_decision(BadQueueName())
    non_json = queue_is_job_json_name_decision("asset.txt")
    reserved = queue_is_job_json_name_decision("asset.qmeta.json")
    embedded = queue_is_job_json_name_decision("asset.claim.payload.json")
    accepted = queue_is_job_json_name_decision("asset.json")

    assert isinstance(missing, QueueJobNameDecision)
    assert missing.accepted is False
    assert missing.reason == "process_queue_identity_name_rejected"
    assert non_json == QueueJobNameDecision(False, "asset.txt", "not_json_queue_job_name", "str")
    assert reserved == QueueJobNameDecision(False, "asset.qmeta.json", "reserved_queue_sidecar_name", "str")
    assert embedded == QueueJobNameDecision(False, "asset.claim.payload.json", "embedded_queue_sidecar_marker", "str")
    assert accepted == QueueJobNameDecision(True, "asset.json", "accepted_queue_job_json_name", "str")
    assert "process_queue_identity_name_parse_failed" in _failure_wheres()

    with pytest.raises(FrozenInstanceError):
        accepted.reason = "mutated"  # type: ignore[misc]


def test_stage2115_queue_identity_public_bool_wrappers_preserve_compatibility() -> None:
    assert queue_is_job_json_name("asset.json") is True
    assert queue_is_job_json_name("asset.txt") is False
    assert queue_is_job_json_name("asset.failure.tmp") is False


def test_stage2115_identity_index_invalidation_decision_records_path_failures() -> None:
    clear_failure_records()

    skipped = invalidate_identity_index_decision(None)
    failed = invalidate_identity_index_decision(UntrustedQueueDir())

    assert skipped == IdentityIndexInvalidationDecision(
        True,
        "identity_index_invalidation_not_required",
        "NoneType",
    )
    assert failed.succeeded is False
    assert failed.queue_dir_type == "UntrustedQueueDir"
    assert failed.reason != ""
    assert "process_queue_identity_index_invalidate_failed" in _failure_wheres()
    assert invalidate_identity_index(UntrustedQueueDir()) is False

    with pytest.raises(FrozenInstanceError):
        failed.reason = "mutated"  # type: ignore[misc]
