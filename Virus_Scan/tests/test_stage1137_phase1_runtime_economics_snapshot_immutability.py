from __future__ import annotations

import pytest

from Virus_Scan.runtime.runtime_economics_ledger import (
    get_runtime_economics_ledger,
    observe_runtime_economics,
)


def test_stage1137_runtime_economics_snapshot_is_immutable_and_detached():
    ledger = get_runtime_economics_ledger()
    observe_runtime_economics("replay_cost", 2.0)

    before = ledger.snapshot()
    replay_before = before.get("replay_cost", 0.0)

    with pytest.raises(TypeError):
        before["replay_cost"] = 0.0  # type: ignore[index]

    observe_runtime_economics("replay_cost", 1.0)
    after = ledger.snapshot()

    assert before.get("replay_cost", 0.0) == replay_before
    assert after.get("replay_cost", 0.0) == replay_before + 1.0


def test_stage1137_runtime_economics_snapshot_materializes_sorted_float_values():
    ledger = get_runtime_economics_ledger()
    observe_runtime_economics("stage1137_custom_cost", 1)

    snapshot = ledger.snapshot()

    assert tuple(snapshot) == tuple(sorted(snapshot))
    assert isinstance(snapshot["stage1137_custom_cost"], float)
