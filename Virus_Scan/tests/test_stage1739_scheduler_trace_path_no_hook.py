"""Stage 1739: scheduler trace writer rejects hostile path-like objects."""

from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.trace_writer import write_scheduler_trace


class HostileTracePath:
    touched = 0

    def __fspath__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned fspath hook must not execute")

    def __str__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned str hook must not execute")

    def __repr__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned repr hook must not execute")


def test_stage1739_trace_writer_rejects_hostile_path_without_hooks() -> None:
    HostileTracePath.touched = 0
    writer_called = False

    def fake_writer(*args, **kwargs):  # pragma: no cover - failure if invoked
        nonlocal writer_called
        writer_called = True
        raise AssertionError("writer must not be called for rejected trace path")

    evidence_record = SchedulerEvidenceRecord(stage="trace", state="ok", message="trace record")
    result = write_scheduler_trace(
        HostileTracePath(),
        (evidence_record,),
        write_json=fake_writer,
    )

    assert HostileTracePath.touched == 0
    assert writer_called is False
    assert result.status == "failed"
    assert result.fatal is True
    assert result.trace_path == ""
    evidence = result.evidence[0]
    assert evidence.error_category == "trace_path_rejected"
    assert evidence.context["trace_path_type"] == "HostileTracePath"
    assert evidence.final_json_must_record is True
    assert evidence.checkpoint_must_record is True
    assert evidence.replay_must_record is True


def test_stage1739_trace_writer_preserves_builtin_path_inputs(tmp_path: Path) -> None:
    writes: list[tuple[str, str, str]] = []
    evidence_record = SchedulerEvidenceRecord(stage="trace", state="ok", message="trace record")

    def fake_writer(tmp, final, payload, *, log_context):
        writes.append((Path(tmp).name, Path(final).name, log_context))
        assert payload["scheduler_trace"][0]["stage"] == "trace"
        return True

    trace_path = tmp_path / "scheduler.trace.json"
    result = write_scheduler_trace(
        trace_path,
        (evidence_record,),
        write_json=fake_writer,
    )

    assert result.status == "written"
    assert result.trace_path == str(trace_path)
    assert writes == [("scheduler.trace.json.tmp", "scheduler.trace.json", "scheduler_trace")]
