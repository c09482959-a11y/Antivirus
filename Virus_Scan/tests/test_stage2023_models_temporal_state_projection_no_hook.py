from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from Virus_Scan.models import temporal
from Virus_Scan.models.temporal import state_projection
from Virus_Scan.runtime.temporal_state import (
    load_temporal_runtime_state,
    temporal_runtime_state_to_json,
)
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.tests.support.static_inventory import read_python_file


class HostileMapping(dict):
    touched = 0

    def _touch(self):
        type(self).touched += 1
        raise AssertionError("caller-owned mapping hook was invoked")

    def __iter__(self):
        return self._touch()

    def get(self, *_args, **_kwargs):
        return self._touch()

    def items(self):
        return self._touch()


class HostileNumeric:
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned float hook was invoked")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness hook was invoked")


class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned text hook was invoked")

    def __format__(self, _spec):
        type(self).touched += 1
        raise AssertionError("caller-owned format hook was invoked")


def test_stage2023_temporal_runtime_loader_rejects_hostile_state_hooks() -> None:
    HostileMapping.touched = 0
    assert load_temporal_runtime_state(HostileMapping()) == {
        "loaded": False, "reason": "temporal_state_non_mapping",
    }
    assert HostileMapping.touched == 0

    node = "stage2023-temporal-state-projection"
    temporal.update_temporal(
        node, "runtime", ("download",),
        learning_decision=accepted_learning_decision(
            target_names=("temporal",), observation_id="stage2023-state-valid",
        ),
    )
    record = deepcopy(temporal_runtime_state_to_json())
    HostileNumeric.touched = 0
    record["nodes"][node]["belief"] = HostileNumeric()
    result = load_temporal_runtime_state(record)
    assert result["loaded"] is False
    assert HostileNumeric.touched == 0


def test_stage2023_temporal_drift_rejects_hostile_node_text_without_hooks() -> None:
    HostileText.touched = 0
    assert state_projection.explain_temporal_drift(HostileText()) == []
    assert HostileText.touched == 0


def test_stage2023_temporal_state_projection_source_removed_backlog_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/models/temporal/state_projection.py"))

    forbidden = (
        "safe_clamp(score / 10.0)",
        "drift_events.append(f'",
        "known_chain + fast_chain_boost",
        "float(hidden_state.get('suspicion'",
        "state.get('history', [])",
        "state.get('hidden_state', {})",
    )
    for snippet in forbidden:
        assert snippet not in source
