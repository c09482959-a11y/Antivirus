from pathlib import Path

import pytest

from Virus_Scan.scheduler.queue import claim_candidates


class HostileName:
    hits = 0

    __slots__ = ()

    @classmethod
    def touch(cls):
        cls.hits += 1
        raise AssertionError("hostile name hook executed")

    def __str__(self):
        return type(self).touch()

    def __repr__(self):
        return type(self).touch()

    def __format__(self, _spec):
        return type(self).touch()

    def __bool__(self):
        return type(self).touch()

    def __iter__(self):
        return type(self).touch()


class HostileLimit:
    hits = 0

    __slots__ = ()

    @classmethod
    def touch(cls):
        cls.hits += 1
        raise AssertionError("hostile limit hook executed")

    def __str__(self):
        return type(self).touch()

    def __repr__(self):
        return type(self).touch()

    def __format__(self, _spec):
        return type(self).touch()

    def __bool__(self):
        return type(self).touch()

    def __int__(self):
        return type(self).touch()


def _is_job_name(name: str) -> bool:
    return name.endswith(".json")


def test_pending_claim_name_field_rejection_uses_exact_index_without_hooks():
    HostileName.hits = 0
    events = []

    result = claim_candidates.pending_claim_names(
        "pending",
        listdir=lambda _path: [HostileName(), "b.json", "a.json"],
        is_job_name=_is_job_name,
        limit=10,
        record_failure=lambda where, exc, **kwargs: events.append((where, kwargs)),
    )

    assert result == ["a.json", "b.json"]
    assert HostileName.hits == 0
    assert events[0][0] == "queue_pending_claim_name_rejected"
    evidence = events[0][1]["extra"]["pending_claim_names_failure"]
    assert evidence["field_name"] == "pending_claim_name_0"
    assert evidence["final_json_must_record"] is True


def test_pending_claim_limit_rejections_record_explicit_evidence_without_default_fallback():
    events = []

    result = claim_candidates.pending_claim_names(
        "pending",
        listdir=lambda _path: ["b.json", "a.json"],
        is_job_name=_is_job_name,
        limit=0,
        record_failure=lambda where, exc, **kwargs: events.append((where, kwargs)),
    )

    assert result == ["a.json", "b.json"]
    assert events[0][0] == "queue_pending_claim_limit_rejected"
    evidence = events[0][1]["extra"]["pending_claim_names_failure"]
    assert evidence["pending_claim_limit_rejected"] is True
    assert evidence["reason"] == "pending_claim_limit_non_positive"
    assert evidence["candidate_count_limit"] == 2
    assert evidence["final_json_must_record"] is True


def test_hostile_limit_rejected_without_hooks_and_uses_candidate_count_limit():
    HostileLimit.hits = 0
    events = []

    result = claim_candidates.pending_claim_names(
        "pending",
        listdir=lambda _path: ["b.json", "a.json"],
        is_job_name=_is_job_name,
        limit=HostileLimit(),
        record_failure=lambda where, exc, **kwargs: events.append((where, kwargs)),
    )

    assert result == ["a.json", "b.json"]
    assert HostileLimit.hits == 0
    assert events[0][0] == "queue_pending_claim_limit_rejected"
    evidence = events[0][1]["extra"]["pending_claim_names_failure"]
    assert evidence["unsupported_scheduler_value"] is True
    assert evidence["field_name"] == "pending_claim_limit"


def test_pending_claim_failure_recorder_failure_is_not_silent_success():
    def failing_record(*_args, **_kwargs):
        raise RuntimeError("recorder failed")

    with pytest.raises(RuntimeError, match="queue_pending_claim_name_rejected_record_failed"):
        claim_candidates.pending_claim_names(
            "pending",
            listdir=lambda _path: [HostileName(), "a.json"],
            is_job_name=_is_job_name,
            limit=10,
            record_failure=failing_record,
        )


def test_claim_candidates_source_has_no_pending_claim_name_fstring_or_fallback_route():
    source = Path(claim_candidates.__file__).read_text(encoding="utf-8")
    assert 'f"pending_claim_name_{index}"' not in source
    assert "_safe_limit" not in source
    assert "fallback" not in source
    assert "return None" not in source
