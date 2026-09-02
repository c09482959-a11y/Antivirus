from pathlib import Path

from Virus_Scan.scheduler.queue import claim_failures


class HostileScalar:
    def __init__(self):
        self.hits = []

    def __str__(self):  # pragma: no cover - failure path if called
        self.hits.append("str")
        raise AssertionError("__str__ must not be called")

    def __repr__(self):  # pragma: no cover - failure path if called
        self.hits.append("repr")
        raise AssertionError("__repr__ must not be called")

    def __format__(self, spec):  # pragma: no cover - failure path if called
        self.hits.append("format")
        raise AssertionError("__format__ must not be called")

    def __bool__(self):  # pragma: no cover - failure path if called
        self.hits.append("bool")
        raise AssertionError("__bool__ must not be called")

    def __iter__(self):  # pragma: no cover - failure path if called
        self.hits.append("iter")
        raise AssertionError("__iter__ must not be called")


class HostilePath(HostileScalar):
    @property
    def name(self):  # pragma: no cover - failure path if called
        self.hits.append("name")
        raise AssertionError("path.name must not be called")

    @property
    def parent(self):  # pragma: no cover - failure path if called
        self.hits.append("parent")
        raise AssertionError("path.parent must not be called")


class HostileMapping(HostileScalar):
    def items(self):  # pragma: no cover - failure path if called
        self.hits.append("items")
        raise AssertionError("items must not be called")

    def get(self, key, default=None):  # pragma: no cover - failure path if called
        self.hits.append("get")
        raise AssertionError("get must not be called")


class Recorder:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.calls = []

    def __call__(self, path, *, reason, job, identity):
        self.calls.append((path, reason, job, identity))
        if self.fail:
            raise RuntimeError("quarantine failed")
        return True


def test_quarantine_reason_rejection_uses_explicit_reason_without_hooks():
    hostile_reason = HostileScalar()
    hostile_path = HostilePath()
    hostile_job = HostileMapping()
    recorder = Recorder()

    claim_failures.quarantine_invalid_claim(
        hostile_path,
        reason=hostile_reason,
        job=hostile_job,
        identity={"job": "abc"},
        quarantine=recorder,
    )

    assert recorder.calls
    path, reason, job, identity = recorder.calls[0]
    assert path is hostile_path
    assert reason == "queue_claim_quarantine_reason_rejected"
    assert job == {"queue_job_unreadable": True, "queue_job_type": "HostileMapping"}
    assert identity == {"job": "abc"}
    assert hostile_reason.hits == []
    assert hostile_path.hits == []
    assert hostile_job.hits == []


def test_quarantine_failure_stage_uses_concat_not_fstring_and_records_reason_issue():
    hostile_reason = HostileScalar()
    recorder = Recorder(fail=True)

    claim_failures.quarantine_invalid_claim(
        "claim.json",
        reason=hostile_reason,
        job={"job": "abc"},
        identity=None,
        quarantine=recorder,
    )

    stage, issue = claim_failures._claim_telemetry_stage(None, "queue_claim_quarantine_reason_rejected")

    assert stage == "queue_claim_quarantine_reason_rejected_quarantine_failed"
    assert issue == "queue_claim_telemetry_stage_missing"
    assert hostile_reason.hits == []


def test_validation_reason_rejects_hostile_mapping_and_default_without_hooks():
    hostile_validation = HostileMapping()
    hostile_default = HostileScalar()

    assert claim_failures.validation_reason(hostile_validation, hostile_default) == "queue_claim_validation_error_rejected"

    assert hostile_validation.hits == []
    assert hostile_default.hits == []


def test_validation_reason_rejects_hostile_stage_without_default_fallback():
    hostile_stage = HostileScalar()
    hostile_default = HostileScalar()

    assert claim_failures.validation_reason({"stage": hostile_stage}, hostile_default) == "queue_claim_validation_stage_rejected"

    assert hostile_stage.hits == []
    assert hostile_default.hits == []


def test_validation_reason_reports_missing_or_empty_stage_explicitly():
    assert claim_failures.validation_reason({}, "queue_claim_invalid") == "queue_claim_validation_stage_missing"
    assert claim_failures.validation_reason({"stage": ""}, "queue_claim_invalid") == "queue_claim_validation_stage_empty"
    assert claim_failures.validation_reason({"stage": "claim_validation_failed"}, "queue_claim_invalid") == "claim_validation_failed"


def test_claim_failures_source_has_no_fallback_or_fstring_routes():
    source = Path(claim_failures.__file__).read_text(encoding="utf-8")

    forbidden = (
        'fallback=',
        'replacement_text=',
        'f"',
        "f'",
        'return None',
        'safe_default',
        'telemetry_stage or',
    )
    for token in forbidden:
        assert token not in source
