from __future__ import annotations

import inspect

from Virus_Scan.scheduler.ownership import raw_queue_claim_values
from Virus_Scan.scheduler.ownership.raw_queue_claim_values import claim_sequence, claim_text


class HostileClaimField:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("format hook executed")


def test_stage1870_claim_value_field_names_reject_hostile_field_without_hooks():
    HostileClaimField.reset()
    reports: list[tuple[object, object, dict[str, object]]] = []
    hostile_field = HostileClaimField()

    text, text_reason = claim_text(object(), field=hostile_field, report=lambda *args, **kwargs: reports.append((args, kwargs)))
    item, sequence_reason = claim_sequence(object(), field=hostile_field, report=lambda *args, **kwargs: reports.append((args, kwargs)))

    assert HostileClaimField.touched == 0
    assert text == ""
    assert item is None
    assert text_reason == "queue_claim_field_rejected"
    assert sequence_reason == "queue_claim_field_rejected"
    assert reports


def test_stage1870_claim_value_source_has_no_field_fstrings():
    source = inspect.getsource(raw_queue_claim_values)

    assert 'f"queue_claim_{field}_missing"' not in source
    assert 'f"queue_claim_{field}_rejected"' not in source
    assert 'f"queue_claim_{field}_materialization_failed"' not in source
    assert "queue_claim_" + str.__str__("file") + "_missing" == "queue_claim_file_missing"
