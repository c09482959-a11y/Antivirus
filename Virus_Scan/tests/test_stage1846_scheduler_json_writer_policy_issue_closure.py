"""Stage 1846: scheduler JSON writer policy fallback closure."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.evidence.scheduler_json_writer import raw_chunk_bytes, raw_queue_enabled, raw_queue_max_chunks, raw_queue_min_bytes


class HostilePolicyValue:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("policy value __str__ must not be invoked")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("policy value __int__ must not be invoked")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("policy value __bool__ must not be invoked")


def test_stage1846_raw_policy_rejections_use_issue_labels_without_hooks() -> None:
    HostilePolicyValue.touched = 0
    records: list[str] = []
    hostile = HostilePolicyValue()

    def runtime_value(_name: str, _default: object) -> object:
        return hostile

    def record(where: str, _exc: BaseException) -> None:
        records.append(where)

    assert raw_chunk_bytes(runtime_value=runtime_value, record_suppressed=record) == 65536
    assert raw_queue_max_chunks(runtime_value=runtime_value, record_suppressed=record) == 192
    assert raw_queue_min_bytes(runtime_value=runtime_value, record_suppressed=record) == 0
    assert raw_queue_enabled(runtime_value=runtime_value, record_suppressed=record) is False

    assert HostilePolicyValue.touched == 0
    assert records == [
        "raw_queue_chunk_bytes_policy_issue",
        "raw_queue_max_chunks_policy_issue",
        "raw_queue_min_bytes_policy_issue",
        "raw_queue_enabled_policy_issue",
    ]


def test_stage1846_scheduler_json_writer_sources_close_policy_fallback_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    writer_source = (root / "scheduler/evidence/scheduler_json_writer.py").read_text(encoding="utf-8")
    support_source = (root / "scheduler/evidence/scheduler_json_writer_support.py").read_text(encoding="utf-8")
    combined_source = "\n".join((writer_source, support_source))

    for forbidden in (
        "_record_raw_policy_fallback",
        "policy_fallback",
        "fallback=",
        "f\"{label}",
    ):
        assert forbidden not in combined_source

    assert "_record_raw_policy_issue" in writer_source
    assert "raw_policy_int(" in writer_source
