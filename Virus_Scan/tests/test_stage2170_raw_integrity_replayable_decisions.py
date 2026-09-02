from __future__ import annotations

from Virus_Scan.scheduler.queue.raw_integrity import _exact_truthy_integrity_value, raw_integrity_degraded
from Virus_Scan.scheduler.queue.raw_integrity_decisions import (
    raw_integrity_degraded_decision,
    raw_integrity_truthy_decision,
)


class HostileIntegrityValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - touching proves unsafe route
        type(self).touched += 1
        raise AssertionError("raw integrity called __bool__")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw integrity called __iter__")

    def __len__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw integrity called __len__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw integrity called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw integrity called __repr__")


class HostileIntegrityMapping(HostileIntegrityValue):
    def items(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw integrity called items")



def test_stage2170_raw_integrity_truthy_projection_is_replayable_without_hooks() -> None:
    HostileIntegrityValue.touched = 0

    missing = raw_integrity_truthy_decision(None)
    unsupported = raw_integrity_truthy_decision(HostileIntegrityValue())

    assert missing.as_bool() is False
    assert missing.reason == "raw_integrity_value_missing"
    assert unsupported.as_bool() is True
    assert unsupported.reason == "raw_integrity_unsupported_value_assumed_truthy"
    assert _exact_truthy_integrity_value(None) is False
    assert HostileIntegrityValue.touched == 0



def test_stage2170_raw_integrity_degraded_projection_is_replayable_without_hooks() -> None:
    HostileIntegrityMapping.touched = 0

    missing = raw_integrity_degraded_decision(None)
    clean = raw_integrity_degraded_decision({"raw_failed": 0, "raw_failures": []})
    degraded = raw_integrity_degraded_decision({"raw_failed": 1})
    rejected = raw_integrity_degraded_decision(HostileIntegrityMapping())

    assert missing.as_bool() is False
    assert missing.reason == "raw_integrity_no_degraded_keys"
    assert clean.as_bool() is False
    assert degraded.as_bool() is True
    assert degraded.matched_key == "raw_failed"
    assert raw_integrity_degraded({"partial_retry": True}) is True
    assert rejected.as_bool() is True
    assert rejected.reason == "raw_integrity_snapshot_rejected"
    assert HostileIntegrityMapping.touched == 0
