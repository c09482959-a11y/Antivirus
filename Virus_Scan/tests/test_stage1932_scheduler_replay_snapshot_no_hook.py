from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scheduler.api.contracts import HybridQueueStateError
from Virus_Scan.scheduler.replay import replay_snapshot
from Virus_Scan.scheduler.replay.replay_snapshot import hybrid_queue_key, hybrid_queue_state_get


class HostileQueueDirectory:
    touched: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.touched = []

    def __fspath__(self):  # pragma: no cover - failure path
        type(self).touched.append("fspath")
        raise AssertionError("__fspath__ must not be called")

    def __str__(self):  # pragma: no cover - failure path
        type(self).touched.append("str")
        raise AssertionError("__str__ must not be called")

    def __repr__(self):  # pragma: no cover - failure path
        type(self).touched.append("repr")
        raise AssertionError("__repr__ must not be called")

    def __bool__(self):  # pragma: no cover - failure path
        type(self).touched.append("bool")
        raise AssertionError("__bool__ must not be called")


def test_stage1932_hybrid_queue_key_rejects_hostile_directory_without_hooks() -> None:
    HostileQueueDirectory.reset()

    with pytest.raises(HybridQueueStateError, match="scheduler_path_rejected"):
        hybrid_queue_key(HostileQueueDirectory())

    assert HostileQueueDirectory.touched == []


def test_stage1932_hybrid_queue_state_get_reports_invalid_directory_without_hooks() -> None:
    HostileQueueDirectory.reset()
    events: list[tuple[str, str]] = []

    result = hybrid_queue_state_get(
        HostileQueueDirectory(),
        report=lambda where, exc: events.append((where, type(exc).__name__)),
    )

    assert result is None
    assert events == [("hybrid_queue_state_get_invalid", "HybridQueueStateError")]
    assert HostileQueueDirectory.touched == []


def test_stage1932_replay_snapshot_source_closes_known_hook_rows() -> None:
    source = Path(replay_snapshot.__file__).read_text(encoding="utf-8")

    forbidden_snippets = (
        "f\"invalid hybrid queue directory:{reason or 'scheduler_path_missing'}\"",
        "raise HybridQueueStateError(f\"invalid hybrid queue state file: {path}\") from exc",
        "raise HybridQueueStateError(f\"invalid hybrid queue state payload: {path}\")",
        "path.name + f\".{os.getpid()}.tmp\"",
        "raise HybridQueueStateError(f\"failed to write and clean hybrid queue state: {path}\") from cleanup_exc",
        "raise HybridQueueStateError(f\"failed to write hybrid queue state: {path}\") from exc",
        "clean_delta.items()",
        "sorted(base.items())",
        "return None\n\n\ndef hybrid_queue_state_set",
    )
    for snippet in forbidden_snippets:
        assert snippet not in source
