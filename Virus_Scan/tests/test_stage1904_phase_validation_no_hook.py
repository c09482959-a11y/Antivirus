from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

import pytest

from Virus_Scan.scheduler.queue.phase_validation import (
    ResultPublicationValidationRequest,
    _validate_recovery_decision_batch,
    validate_result_publication,
    _validate_terminal_job_accounting,
)
from Virus_Scan.scheduler.queue.recovery_contracts import QueueRecoveryDecision


class HostileValue:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iter")


def _decision(job_id: str, worker_id: str = "worker-1") -> QueueRecoveryDecision:
    return QueueRecoveryDecision(
        job_id=job_id,
        worker_id=worker_id,
        file_path="/tmp/sample.bin",
        failure_reason="timeout",
        final_action="fail",
        reason_text="timeout",
        attempt_count=1,
        source_event="stage1904",
    )


def test_stage1904_result_publication_sets_and_owner_mismatch_do_not_call_hooks() -> None:
    HostileValue.touched = 0

    with pytest.raises(RuntimeError, match="unknown job"):
        validate_result_publication(ResultPublicationValidationRequest(
            {"job_id": "job-a", "file": "/tmp/stage1904.bin"},
            HostileValue(),
            ["job-a"],
            [HostileValue()],
            worker_id="worker-1",
            published_file_identities=[HostileValue()],
        ))
    assert HostileValue.touched == 0

    with pytest.raises(RuntimeError, match="worker ownership mismatch"):
        validate_result_publication(ResultPublicationValidationRequest(
            {"job_id": "job-a", "file": "/tmp/stage1904.bin"},
            ["job-a"],
            ["job-a"],
            [],
            worker_id="worker-1",
            worker_ownership={"job-a": HostileValue()},
        ))
    assert HostileValue.touched == 0


def test_stage1904_recovery_and_terminal_validation_messages_are_owned_text() -> None:
    first = _decision("job-a")
    duplicate = _decision("job-a", worker_id="worker-2")
    with pytest.raises(RuntimeError, match="duplicate scheduler recovery decision"):
        _validate_recovery_decision_batch([first, duplicate])


    HostileValue.touched = 0
    with pytest.raises(RuntimeError, match="claimed scheduler jobs lack final state"):
        _validate_terminal_job_accounting([HostileValue()], [], [])
    assert HostileValue.touched == 0


def test_stage1904_phase_validation_source_has_no_raw_str_or_fstring_routes() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/queue/phase_validation.py"))

    assert "str(x) for x in (known_jobs or ())" not in source
    assert "str(x) for x in (claimed_jobs or ())" not in source
    assert "str(x) for x in (published_identities or ())" not in source
    assert "str(job) for job in (claimed_jobs or ())" not in source
    assert "worker_ownership and worker_id" not in source
    assert "worker_ownership.get(identity)" not in source
    assert "str(owner) != str(worker_id)" not in source
    assert 'f"scheduler result for unknown job: {identity}"' not in source
    assert 'f"scheduler result for unclaimed job: {identity}"' not in source
    assert 'f"scheduler worker ownership mismatch for {identity}: owner={owner} reporter={worker_id}"' not in source
    assert 'f"duplicate scheduler recovery decision for job: {decision.job_id}"' not in source
    assert 'f"duplicate scheduler worker recovery accounting: {decision.worker_id}:{decision.job_id}"' not in source
    assert 'f"claimed scheduler jobs lack final state: {\', \'.join(missing)}"' not in source
