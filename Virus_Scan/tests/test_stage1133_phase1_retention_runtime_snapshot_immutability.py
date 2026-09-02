from __future__ import annotations

import pytest
from types import MappingProxyType

from Virus_Scan.runtime.retention_runtime_state import RetentionRuntimeState


def test_stage1133_retention_runtime_snapshot_is_immutable_and_detached() -> None:
    state = RetentionRuntimeState()
    state.should_prune(10)

    snapshot = state.snapshot()

    assert isinstance(snapshot, MappingProxyType)
    assert snapshot["prune_update_count"] == 1
    with pytest.raises(TypeError):
        snapshot["prune_update_count"] = 99  # type: ignore[index]

    state.should_prune(10)

    assert snapshot["prune_update_count"] == 1
    assert state.snapshot()["prune_update_count"] == 2


def test_stage1133_retention_runtime_snapshot_preserves_reset_semantics() -> None:
    state = RetentionRuntimeState()

    assert state.should_prune(2) is False
    before_reset = state.snapshot()
    assert before_reset["prune_update_count"] == 1

    assert state.should_prune(2) is True
    after_reset = state.snapshot()

    assert after_reset["prune_update_count"] == 0
    assert before_reset["prune_update_count"] == 1
