from __future__ import annotations

import inspect

from Virus_Scan.scheduler.ownership import raw_queue_claim_validation
from Virus_Scan.scheduler.ownership.raw_queue_claim_validation import repair_and_validate_claim_job


class HostileJobValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __iter__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("iter hook executed")

    def __str__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("repr hook executed")


def test_stage1870_raw_queue_claim_exact_dict_copy_does_not_iterate_hostile_values():
    HostileJobValue.reset()
    hostile = HostileJobValue()
    job = {"job_type": "file", "file": "game.bin", "payload": hostile}

    normalized, failure = repair_and_validate_claim_job("queue", job)

    assert HostileJobValue.touched == 0
    assert failure is None
    assert normalized["payload"] is hostile


def test_stage1870_raw_queue_claim_validation_source_uses_exact_dict_copy():
    source = inspect.getsource(raw_queue_claim_validation)

    assert "normalized = dict(dict.items(job))" not in source
    assert "normalized = dict.copy(job)" in source
