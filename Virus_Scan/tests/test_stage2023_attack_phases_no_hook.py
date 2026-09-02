from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.tags.heuristics.attack_phases import classify_attack_graph_phases
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence



class HostileTags:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("hostile tag hook")

    def __bool__(self):  # pragma: no cover - failure proves hook execution
        return self._touch()

    def __iter__(self):  # pragma: no cover
        return self._touch()

    def __str__(self):  # pragma: no cover
        return self._touch()

    def __repr__(self):  # pragma: no cover
        return self._touch()


def test_stage2023_attack_phase_classifier_rejects_hostile_tags_without_hooks() -> None:
    HostileTags.reset()

    result = classify_attack_graph_phases(HostileTags(), evaluate_chain_evidence())

    assert result == {'phase_score': 0.0, 'raw_phase_score': 0.0, 'phase_hits': {}}
    assert HostileTags.touched == 0


def test_stage2023_attack_phase_classifier_preserves_concrete_phase_hits() -> None:
    tags = physical_tag_evidence((
        "powershell_exec",
        "schtasks_create",
        "network_exfiltration",
    ))
    result = classify_attack_graph_phases(
        tags,
        evaluate_chain_evidence(tags=tags),
    )

    assert result["phase_score"] > 0.0
    assert result["phase_hits"]["execution"]["matched"] == ["powershell_exec"]
    assert result["phase_hits"]["persistence"]["matched"] == ["schtasks", "schtasks_create"]
    assert "network_exfiltration" in result["phase_hits"]["exfiltration"]["matched"]


def test_stage2023_attack_phase_source_removed_audited_hook_patterns() -> None:
    source = read_python_file(Path("Virus_Scan/detection/tags/heuristics/attack_phases.py"))

    assert "tags or []" not in source
    assert "phase_aliases.items()" not in source
    assert "safe_clamp(total_score / 45.0)" not in source
