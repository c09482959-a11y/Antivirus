from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from pathlib import Path

from Virus_Scan.detection.profiles.renpy.loaders.family_scan import renpy_loader_family_tags
from Virus_Scan.detection.tags.heuristics.behavior_mapping import tag_expected_behavior_mapping
from Virus_Scan.detection.tags.heuristics.blockchain_behavior import detect_blockchain_abuse_tags
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.weighting.chain_bonus import calibrated_chain_bonus
from Virus_Scan.detection.tags.heuristics.persistence_chains import detect_scheduled_task_persistence
from Virus_Scan.detection.tags.heuristics.tag_phase import phase_hits_from_tags


class HostileHeuristicInput:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("hostile heuristic hook")

    def __str__(self):  # pragma: no cover - failure proves hook execution
        return self._touch()

    def __repr__(self):  # pragma: no cover
        return self._touch()

    def __bool__(self):  # pragma: no cover
        return self._touch()

    def __iter__(self):  # pragma: no cover
        return self._touch()

    def __fspath__(self):  # pragma: no cover
        return self._touch()


def test_stage2023_heuristic_singletons_reject_hostile_inputs_without_hooks() -> None:
    HostileHeuristicInput.reset()
    hostile = HostileHeuristicInput()

    assert renpy_loader_family_tags(hostile, path=hostile, pickle_opcode_context=hostile, pickle_exec_context=hostile) == []
    assert detect_blockchain_abuse_tags(hostile) == []
    chain_evidence = evaluate_chain_evidence(
        tags=hostile, ordered_events=hostile, api_calls=hostile,
    )
    assert chain_evidence.decisions == ()
    assert chain_evidence.failures
    assert tag_expected_behavior_mapping(hostile)["role"] == "unknown"
    assert phase_hits_from_tags(hostile) == {}
    assert HostileHeuristicInput.touched == 0


def test_stage2023_heuristic_singletons_preserve_expected_behavior() -> None:
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence((
        "network_download", "file_write", "process_exec",
    )))
    chain_score, chain_hits = calibrated_chain_bonus(evidence)
    assert chain_score > 0.0
    assert any(hit.startswith("chain_bonus:execution.download") for hit in chain_hits)
    persistence_score, persistence_hits = detect_scheduled_task_persistence(["at_exec"])
    assert persistence_score >= 6.0
    assert "at task scheduling" in persistence_hits


def test_stage2023_heuristic_singletons_source_removed_audited_patterns() -> None:
    snippets_by_file = {
        "Virus_Scan/detection/profiles/renpy/loaders/family_scan.py": ("text = str(blob or '').lower()",),
        "Virus_Scan/detection/tags/heuristics/behavior_mapping.py": ('t = str(tag or "").strip().lower()',),
        "Virus_Scan/detection/tags/heuristics/blockchain_behavior.py": ("text = str(blob or '').lower()",),
        "Virus_Scan/detection/tags/heuristics/persistence_chains.py": ("legacy task scheduling",),
        "Virus_Scan/detection/tags/heuristics/tag_phase.py": ("for phase, data in ATTACK_GRAPH.items():",),
    }

    assert not Path(
        "Virus_Scan/detection/tags/heuristics/execution_chains.py"
    ).exists()
    for file_name, snippets in snippets_by_file.items():
        source = Path(file_name).read_text(encoding="utf-8")
        assert [snippet for snippet in snippets if snippet in source] == []
