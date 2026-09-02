"""Stage 1738: scheduler checkpoint writer rejects hostile path-like objects."""

from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.evidence.checkpoint_writer import write_scheduler_checkpoint
from Virus_Scan.scheduler.evidence.records import SchedulerEvidenceBundle


class HostileCheckpointPath:
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


def test_stage1738_checkpoint_writer_rejects_hostile_path_without_hooks() -> None:
    HostileCheckpointPath.touched = 0
    writer_called = False

    def fake_writer(*args, **kwargs):  # pragma: no cover - failure if invoked
        nonlocal writer_called
        writer_called = True
        raise AssertionError("writer must not be called for rejected checkpoint path")

    result = write_scheduler_checkpoint(
        HostileCheckpointPath(),
        SchedulerEvidenceBundle(records=()),
        write_json=fake_writer,
    )

    assert HostileCheckpointPath.touched == 0
    assert writer_called is False
    assert result.status == "failed"
    assert result.fatal is True
    assert result.checkpoint_path == ""
    evidence = result.evidence[0]
    assert evidence.error_category == "checkpoint_path_rejected"
    assert evidence.context["checkpoint_path_type"] == "HostileCheckpointPath"
    assert evidence.final_json_must_record is True
    assert evidence.checkpoint_must_record is True
    assert evidence.replay_must_record is True


def test_stage1738_checkpoint_writer_preserves_builtin_path_inputs(tmp_path: Path) -> None:
    writes: list[tuple[str, str, str]] = []

    def fake_writer(tmp, final, payload, *, log_context):
        writes.append((Path(tmp).name, Path(final).name, log_context))
        assert "scheduler" in payload
        return True

    checkpoint = tmp_path / "scheduler.checkpoint.json"
    result = write_scheduler_checkpoint(
        checkpoint,
        SchedulerEvidenceBundle(records=()),
        write_json=fake_writer,
    )

    assert result.status == "written"
    assert result.checkpoint_path == str(checkpoint)
    assert writes == [("scheduler.checkpoint.json.tmp", "scheduler.checkpoint.json", "scheduler_checkpoint")]
