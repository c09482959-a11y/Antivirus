from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.detection.tags.heuristics.family_heuristics import enhanced_family_heuristics



class HostileFamilyInput:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("hostile family hook")

    def __str__(self):  # pragma: no cover - failure proves hook execution
        return self._touch()

    def __repr__(self):  # pragma: no cover
        return self._touch()

    def __bool__(self):  # pragma: no cover
        return self._touch()

    def __iter__(self):  # pragma: no cover
        return self._touch()


def test_stage2023_family_heuristics_rejects_hostile_inputs_without_hooks() -> None:
    HostileFamilyInput.reset()
    hostile = HostileFamilyInput()

    result = enhanced_family_heuristics(hostile, hostile, strings_blob=hostile, api_calls=hostile)

    assert result["score"] == 0.0
    assert "detection_observation_unavailable" in result["tags"]
    assert HostileFamilyInput.touched == 0


def test_stage2023_family_heuristics_preserves_process_injection_signal() -> None:
    result = enhanced_family_heuristics(
        "sample.ps1",
        ["process_exec"],
        strings_blob="VirtualAlloc WriteProcessMemory",
        api_calls=["CreateRemoteThread"],
    )

    assert result["score"] == 0.65
    assert "process_injection" in result["tags"]
    assert "process_exec" in result["tags"]


def test_stage2023_family_heuristics_source_removed_audited_hook_patterns() -> None:
    source = read_python_file(Path("Virus_Scan/detection/tags/heuristics/family_heuristics.py"))

    assert "str(strings_blob or '').lower()" not in source
    assert "return {'score': safe_clamp(score), 'tags': sorted(new_tags)}" not in source
