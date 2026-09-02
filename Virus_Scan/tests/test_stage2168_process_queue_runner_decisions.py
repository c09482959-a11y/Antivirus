from __future__ import annotations

import pytest
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture

from Virus_Scan.scheduler.execution.process_queue_runner import (
    _has_rejected_scheduler_file,
    run_process_queue,
)
from Virus_Scan.scheduler.execution.process_queue_runner_decisions import (
    process_queue_empty_result_decision,
    scheduler_file_rejection_decision,
)


class HostileUnsupportedDict(dict):
    @property
    def unsupported_scheduler_value(self):  # pragma: no cover - must not be invoked
        raise AssertionError("descriptor path should not be invoked")


def test_scheduler_file_rejection_decision_replays_rejected_file_sentinel_without_hooks() -> None:
    rejected = {"unsupported_scheduler_value": True}
    decision = scheduler_file_rejection_decision(("safe.bin", rejected))

    assert decision.rejected is True
    assert decision.reason == "unsupported_scheduler_file_value_rejected"
    assert decision.rejected_indexes == (1,)
    assert _has_rejected_scheduler_file(("safe.bin", rejected)) is True


def test_scheduler_file_rejection_decision_accepts_safe_files_without_hidden_false() -> None:
    hostile_dict = HostileUnsupportedDict({"unsupported_scheduler_value": False})
    decision = scheduler_file_rejection_decision(("safe.bin", hostile_dict))

    assert decision.rejected is False
    assert decision.reason == "scheduler_files_accepted"
    assert decision.rejected_indexes == ()
    assert _has_rejected_scheduler_file(("safe.bin", hostile_dict)) is False


def test_empty_process_queue_result_is_replayable_and_compatible() -> None:
    decision = process_queue_empty_result_decision(())

    assert decision.accepted is True
    assert decision.reason == "process_queue_empty_input_no_work"
    assert decision.file_count == 0
    assert decision.as_mapping() == {}
    assert run_process_queue("/tmp", [], 1, scan_session_snapshot=scan_session_snapshot_fixture()) == {}


def test_process_queue_rejected_file_path_still_fails_explicitly() -> None:
    with pytest.raises(ValueError, match="process_queue_runner_all_files_rejected"):
        run_process_queue("/tmp", [{"unsupported_scheduler_value": True}], 1, scan_session_snapshot=scan_session_snapshot_fixture())
