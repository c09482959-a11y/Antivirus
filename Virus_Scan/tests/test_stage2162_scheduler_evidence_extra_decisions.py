from __future__ import annotations

import ast
import inspect
import textwrap

from Virus_Scan.scheduler.evidence import inmemory_progress_logging
from Virus_Scan.scheduler.evidence.process_queue_errors import (
    ProcessQueueExtraDecision,
    _process_queue_extra,
    _process_queue_extra_decision,
)
from Virus_Scan.scheduler.evidence.raw_queue_degradation import (
    RawQueueIntegrityMappingDecision,
    _raw_queue_integrity_mapping,
    _raw_queue_integrity_mapping_decision,
)
from Virus_Scan.scheduler.evidence.raw_queue_failure import (
    QueueExtraItemsDecision,
    _queue_extra_items,
    _queue_extra_items_decision,
)
from Virus_Scan.scheduler.evidence.raw_queue_issue import (
    RawQueueIssueExtraDecision,
    _issue_extra,
    _issue_extra_decision,
)


class HostileValue:
    touched = 0

    def __getattribute__(self, name: str):  # pragma: no cover - must not run
        type(self).touched += 1
        raise AssertionError(f"hostile attribute accessed: {name}")

    def __iter__(self):  # pragma: no cover - must not run
        type(self).touched += 1
        raise AssertionError("hostile iter invoked")

    def __len__(self):  # pragma: no cover - must not run
        type(self).touched += 1
        raise AssertionError("hostile len invoked")

    def __bool__(self):  # pragma: no cover - must not run
        type(self).touched += 1
        raise AssertionError("hostile bool invoked")

    def __str__(self):  # pragma: no cover - must not run
        type(self).touched += 1
        raise AssertionError("hostile str invoked")


def _return_expressions(function: object) -> tuple[str, ...]:
    parsed = ast.parse(textwrap.dedent(inspect.getsource(function)))
    return tuple(ast.unparse(node.value) for node in ast.walk(parsed) if isinstance(node, ast.Return))


def test_stage2162_removed_progress_job_record_projection_surface_stays_absent() -> None:
    assert not hasattr(inmemory_progress_logging, "OwnedJobRecordsDecision")
    assert not hasattr(inmemory_progress_logging, "_owned_job_records")
    assert not hasattr(inmemory_progress_logging, "_owned_job_records_decision")


def test_stage2162_optional_scheduler_evidence_absence_is_replayable_decision() -> None:
    process_extra = _process_queue_extra_decision(None)
    assert isinstance(process_extra, ProcessQueueExtraDecision)
    assert process_extra.extra == {}
    assert process_extra.reason == "process_queue_extra_absent"
    assert process_extra.accepted is True
    assert _process_queue_extra(None) == process_extra.extra

    integrity = _raw_queue_integrity_mapping_decision(None)
    assert isinstance(integrity, RawQueueIntegrityMappingDecision)
    assert integrity.mapping == {}
    assert integrity.reason == "raw_queue_integrity_absent"
    assert integrity.accepted is True
    assert _raw_queue_integrity_mapping(None) == integrity.mapping

    failure_extra = _queue_extra_items_decision(None)
    assert isinstance(failure_extra, QueueExtraItemsDecision)
    assert failure_extra.items == ()
    assert failure_extra.reason == "failure_info_extra_absent"
    assert failure_extra.accepted is True
    assert _queue_extra_items(None) == failure_extra.items

    issue_extra = _issue_extra_decision(None)
    assert isinstance(issue_extra, RawQueueIssueExtraDecision)
    assert issue_extra.extra == {}
    assert issue_extra.reason == "raw_queue_issue_extra_absent"
    assert issue_extra.accepted is True
    assert _issue_extra(None) == issue_extra.extra


def test_stage2162_unsupported_scheduler_evidence_carriers_do_not_call_hooks() -> None:
    HostileValue.touched = 0
    value = HostileValue()

    process_extra = _process_queue_extra_decision(value)
    assert process_extra.accepted is False
    assert process_extra.extra["extra_unavailable_reason"] == "unsupported_process_queue_extra"

    integrity = _raw_queue_integrity_mapping_decision(value)
    assert integrity.accepted is False
    assert integrity.mapping["raw_queue_integrity_unavailable"] is True
    assert integrity.mapping["raw_queue_integrity_failure"]["unsupported_scheduler_value"] is True

    failure_extra = _queue_extra_items_decision(value)
    assert failure_extra.accepted is False
    assert failure_extra.items[0][0] == "extra_unavailable"
    assert failure_extra.items[0][1]["unsupported_scheduler_value"] is True

    issue_extra = _issue_extra_decision(value)
    assert issue_extra.accepted is False
    assert issue_extra.extra["raw_queue_extra_unavailable"] is True
    assert issue_extra.extra["raw_queue_extra_failure"]["unsupported_scheduler_value"] is True

    assert HostileValue.touched == 0


def test_stage2162_legacy_projection_wrappers_replay_decision_fields_not_literal_defaults() -> None:
    assert _return_expressions(_process_queue_extra) == ("_process_queue_extra_decision(extra).extra",)
    assert _return_expressions(_raw_queue_integrity_mapping) == ("_raw_queue_integrity_mapping_decision(integrity).mapping",)
    assert _return_expressions(_queue_extra_items) == ("_queue_extra_items_decision(extra).items",)
    assert _return_expressions(_issue_extra) == ("_issue_extra_decision(extra).extra",)
