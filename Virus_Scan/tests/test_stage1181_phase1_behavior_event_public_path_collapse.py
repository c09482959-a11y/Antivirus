from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.detection import tags
from Virus_Scan.detection.models import chain as detection_chain
from Virus_Scan.models import behavior_sequence_contract


DETECTION_CHAIN = Path("Virus_Scan/detection/models/chain.py")
DETECTION_TAGS_INIT = Path("Virus_Scan/detection/tags/__init__.py")
ORDERED_EVENTS = Path("Virus_Scan/detection/correlation/temporal/ordered_events.py")


def _import_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.name)
    return names


def test_stage1181_detection_chain_does_not_reexport_behavior_event_contract():
    assert hasattr(behavior_sequence_contract, "canonical_behavior_event_name")
    assert not hasattr(detection_chain, "canonical_behavior_event_name")
    assert "canonical_behavior_event_name" not in detection_chain.__all__
    assert "canonical_behavior_event_name" not in _import_names(DETECTION_CHAIN)


def test_stage1181_detection_tags_init_has_no_legacy_canonical_alias():
    assert not hasattr(tags, "_canonical_behavior_event_name")
    assert tags.__all__ == ()
    assert "canonical_behavior_event_name" not in _import_names(DETECTION_TAGS_INIT)


def test_stage1181_ordered_events_no_longer_exports_unused_behavior_alias():
    source = ORDERED_EVENTS.read_text(encoding="utf-8")
    assert "_canonical_behavior_event_name" not in source
    assert "canonical_behavior_event_name" not in _import_names(ORDERED_EVENTS)
