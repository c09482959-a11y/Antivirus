import pytest

from Virus_Scan.scheduler.queue.claim_candidates import pending_claim_names
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import (
    QueueListdirFailure,
    queue_listdir_failure,
)


class HostileListing:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("listing iter must not execute")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("listing len must not execute")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("listing bool must not execute")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("listing str must not execute")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("listing repr must not execute")


class HostileName:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("name str must not execute")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("name repr must not execute")


class HostileLimit:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("limit bool must not execute")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("limit int must not execute")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("limit str must not execute")



def _recorder():
    events = []

    def record(where, exc, *, extra=None, fatal=False):
        events.append((where, type(exc).__name__, extra, fatal))
        return True

    return events, record



def _is_job_name(name):
    return name.endswith(".json")



def test_stage1731_listdir_failure_records_evidence_not_silent_empty():
    events, record = _recorder()
    failure = queue_listdir_failure("/tmp/pending", reason="queue_listdir_failed")

    with pytest.raises(QueueListdirFailure):
        pending_claim_names(
            "/tmp/pending",
            listdir=lambda _path: failure,
            is_job_name=_is_job_name,
            limit=10,
            record_failure=record,
        )

    assert events
    where, exc_type, extra, fatal = events[0]
    assert where == "queue_pending_claim_listdir_failed"
    assert exc_type == "RuntimeError"
    assert fatal is True
    assert extra["pending_claim_names_failure"]["queue_listdir_failed"] is True
    assert extra["pending_claim_names_failure"]["final_json_must_record"] is True



def test_stage1731_unsupported_listing_rejected_without_hooks():
    events, record = _recorder()
    HostileListing.touched = 0

    with pytest.raises(QueueListdirFailure):
        pending_claim_names(
            "pending",
            listdir=lambda _path: HostileListing(),
            is_job_name=_is_job_name,
            limit=10,
            record_failure=record,
        )

    assert HostileListing.touched == 0
    assert events[0][0] == "queue_pending_claim_listdir_unsupported"
    evidence = events[0][2]["pending_claim_names_failure"]
    assert evidence["unsupported_scheduler_value"] is True
    assert evidence["field_name"] == "pending_claim_listdir_result"



def test_stage1731_hostile_names_are_rejected_without_predicate_or_string_hooks():
    events, record = _recorder()
    HostileName.touched = 0
    predicate_inputs = []

    def predicate(name):
        predicate_inputs.append(name)
        return name.endswith(".json")

    result = pending_claim_names(
        "pending",
        listdir=lambda _path: [HostileName(), "b.json", "a.txt", "a.json"],
        is_job_name=predicate,
        limit=10,
        record_failure=record,
    )

    assert result == ["a.json", "b.json"]
    assert HostileName.touched == 0
    assert predicate_inputs == ["b.json", "a.txt", "a.json"]
    assert events[0][0] == "queue_pending_claim_name_rejected"



def test_stage1731_hostile_limit_rejected_without_bool_int_or_str_hooks():
    events, record = _recorder()
    HostileLimit.touched = 0

    result = pending_claim_names(
        "pending",
        listdir=lambda _path: ["b.json", "a.json"],
        is_job_name=_is_job_name,
        limit=HostileLimit(),
        record_failure=record,
    )

    assert result == ["a.json", "b.json"]
    assert HostileLimit.touched == 0
    assert events[0][0] == "queue_pending_claim_limit_rejected"



def test_stage1731_valid_names_remain_sorted_and_limited():
    result = pending_claim_names(
        "pending",
        listdir=lambda _path: ["z.json", "a.txt", "b.json", "a.json"],
        is_job_name=_is_job_name,
        limit=2,
    )

    assert result == ["a.json", "b.json"]
