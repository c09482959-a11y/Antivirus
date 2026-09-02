"""Stage 1847: scheduler suppressed failure sentinel/f-string closure."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.evidence import suppressed_failures


class HostileWhere:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("where __str__ must not be invoked")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("where __format__ must not be invoked")


def test_stage1847_process_queue_where_rejects_hostile_without_hooks() -> None:
    HostileWhere.touched = 0
    assert suppressed_failures._process_queue_where(HostileWhere()) == "process_queue.suppression_where_rejected"
    assert HostileWhere.touched == 0


def test_stage1847_suppressed_failure_source_closes_sentinel_and_fstring_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler/evidence/suppressed_failures.py").read_text(encoding="utf-8")
    for forbidden in (
        "return False",
        'f"process_queue.{where}"',
        "format(where",
        "os.fspath",
    ):
        assert forbidden not in source
    assert "SUPPRESSION_RECORD_FAILED" in source
    assert "str.__add__(" in source
