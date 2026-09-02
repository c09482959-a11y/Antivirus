from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.detection.scoring.weighting.noise_gate import cap_noise_only_score



class HostileNoiseInput:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("hostile noise hook")

    def __str__(self):  # pragma: no cover - failure proves hook execution
        return self._touch()

    def __repr__(self):  # pragma: no cover
        return self._touch()

    def __bool__(self):  # pragma: no cover
        return self._touch()

    def __float__(self):  # pragma: no cover
        return self._touch()

    def __int__(self):  # pragma: no cover
        return self._touch()

    def __iter__(self):  # pragma: no cover
        return self._touch()

    def __le__(self, other):  # pragma: no cover
        return self._touch()


def test_stage2023_noise_gate_rejects_hostile_inputs_without_hooks() -> None:
    HostileNoiseInput.reset()
    hostile = HostileNoiseInput()

    score = cap_noise_only_score(
        hostile,
        hostile,
        hostile,
        stage=hostile,
        concrete_count=hostile,
    )

    assert score == 0.0
    assert HostileNoiseInput.touched == 0


def test_stage2023_noise_gate_preserves_asset_entropy_cap() -> None:
    assert cap_noise_only_score(
        90.0,
        ["high_entropy_packed"],
        [],
        stage="asset",
        concrete_count=1,
    ) == 18.0


def test_stage2023_noise_gate_source_removed_audited_hook_patterns() -> None:
    source = read_python_file(Path("Virus_Scan/detection/scoring/weighting/noise_gate.py"))

    assert 'asset = str(stage or "").lower()' not in source
    assert "base = float(score or 0.0)" not in source
