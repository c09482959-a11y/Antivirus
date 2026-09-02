from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.detection.scoring.adaptive.log_odds_weights import log_odds_active_layer_bonus

class HostileActiveLayers:
    def __bool__(self):  # pragma: no cover - used by bool-hostile boundary code
        raise RuntimeError("hostile bool")

    def __int__(self):  # pragma: no cover
        raise RuntimeError("hostile int")


def test_stage1451log_odds_active_layer_bonus_handles_hostile_count() -> None:
    assert log_odds_active_layer_bonus(HostileActiveLayers()) == 0.0


def test_stage1451_clustering_assignment_has_no_dead_suppressed_failure_name() -> None:
    source = read_python_file(Path("Virus_Scan/models/clustering/assignment.py"))
    assert "record_suppressed_failure" not in source
    assert "try:\n            pass" not in source
