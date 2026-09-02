from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

import pytest

from Virus_Scan.contracts.temporal_accumulator import initial_temporal_accumulator_state
from Virus_Scan.models.temporal.accumulator import temporal_evidence_accumulator_update


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
    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness hook was invoked")
    def __float__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned float hook was invoked")


def test_stage2023_temporal_accumulator_rejects_hostile_numeric_hooks() -> None:
    HostileNumeric.touched = 0
    state = temporal_evidence_accumulator_update(
        previous=initial_temporal_accumulator_state(),
        observation=HostileNumeric(), observation_confidence=HostileNumeric(),
        evidence_timestamp=HostileNumeric(), support=0,
    )
    assert state.posterior_belief == 0.0
    assert state.last_evidence_timestamp is None
    assert HostileNumeric.touched == 0


def test_stage2023_temporal_accumulator_rejects_hostile_mapping_hooks() -> None:
    HostileMapping.touched = 0
    with pytest.raises(TypeError, match="temporal accumulator state required"):
        temporal_evidence_accumulator_update(
            previous=HostileMapping(), observation=0.0,
            observation_confidence=0.0, evidence_timestamp=None, support=0,
        )
    assert HostileMapping.touched == 0


def test_stage2023_parallel_decay_owner_is_removed_and_accumulator_has_no_clock() -> None:
    assert not Path("Virus_Scan/models/temporal/decay.py").exists()
    source = read_python_file(Path("Virus_Scan/models/temporal/accumulator.py"))
    assert "time.time" not in source
    assert "import time" not in source
    assert "previous.get" not in source
