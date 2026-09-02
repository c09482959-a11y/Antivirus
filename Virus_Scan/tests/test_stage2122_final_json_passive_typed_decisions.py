from __future__ import annotations

import inspect

from Virus_Scan.scheduler.evidence.final_json_passive_decisions import scheduler_status_key_decision
from Virus_Scan.scheduler.evidence.final_json_passive_scalar import (
    scalar_failure_category,
    scalar_failure_category_decision,
)
from Virus_Scan.scheduler.evidence.final_json_passive_status_projection import _is_scheduler_status_key


_DOMAIN_FRAGMENTS = (
    "scheduler", "queue", "worker", "timeout", "retry", "replay", "checkpoint", "trace", "orphan",
)
_STATUS_FRAGMENTS = (
    "status", "state", "result", "failure", "failed", "fatal", "degraded", "suppressed_failures",
)
_SPECIFIC_PROJECTION_FIELDS = (
    "checkpoint", "checkpoint_status", "scheduler_checkpoint",
    "replay_comparison_result", "replay_result", "replay_status", "scheduler_replay",
    "queue_integrity_result", "queue_recovery_result", "orphan_recovery_result", "queue_merge_result",
    "timeout_result", "timeout_decision", "retry_decision", "retry_result", "retry_exhaustion_result",
    "worker_result", "worker_lifecycle_result", "worker_snapshot",
    "trace", "trace_status", "scheduler_trace", "scheduler_trace_status",
    "trace_write_result", "scheduler_trace_write_result",
)


def test_passive_scalar_clean_and_rejected_categories_are_replayable_decisions() -> None:
    missing = scalar_failure_category_decision("suppressed_failures", None)
    assert missing.category == ""
    assert missing.failure_present is False
    assert missing.unsupported is False
    assert missing.reason == "suppressed_failures_missing"

    positive = scalar_failure_category_decision("suppressed_failures", "2")
    assert positive.category == "suppressed_failures_failure"
    assert positive.failure_present is True
    assert positive.reason == "suppressed_failures_positive_count"

    rejected = scalar_failure_category_decision("queue_status", object())
    assert rejected.category == "queue_status_unsupported"
    assert rejected.unsupported is True
    assert rejected.reason == "passive_scalar_empty_unsupported_value"

    assert scalar_failure_category("queue_failed", False) == ""
    assert scalar_failure_category("queue_failed", True) == "queue_failed_failure"


def test_passive_scalar_public_wrapper_no_longer_returns_hidden_empty_literal() -> None:
    source = inspect.getsource(scalar_failure_category)
    assert 'return ""' not in source
    assert "scalar_failure_category_decision" in source


def test_passive_status_key_rejections_are_typed_decisions() -> None:
    evidence = scheduler_status_key_decision(
        "evidence",
        domain_fragments=_DOMAIN_FRAGMENTS,
        status_fragments=_STATUS_FRAGMENTS,
        specific_projection_fields=_SPECIFIC_PROJECTION_FIELDS,
    )
    assert evidence.accepted is False
    assert evidence.reason == "scheduler_status_evidence_field_rejected"

    specific = scheduler_status_key_decision(
        "worker_result",
        domain_fragments=_DOMAIN_FRAGMENTS,
        status_fragments=_STATUS_FRAGMENTS,
        specific_projection_fields=_SPECIFIC_PROJECTION_FIELDS,
    )
    assert specific.accepted is False
    assert specific.reason == "scheduler_status_specific_projection_owner"

    matched = scheduler_status_key_decision(
        "queue_custom_status",
        domain_fragments=_DOMAIN_FRAGMENTS,
        status_fragments=_STATUS_FRAGMENTS,
        specific_projection_fields=_SPECIFIC_PROJECTION_FIELDS,
    )
    assert matched.accepted is True
    assert matched.reason == "scheduler_status_domain_fragment_match"

    assert _is_scheduler_status_key("scheduler") is True
    assert _is_scheduler_status_key("trace_status") is False


def test_passive_status_key_wrapper_no_longer_returns_hidden_false_literal() -> None:
    source = inspect.getsource(_is_scheduler_status_key)
    assert "return False" not in source
    assert "scheduler_status_key_decision" in source
