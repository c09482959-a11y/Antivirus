from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.publication import json_writer
from Virus_Scan.publication.api import pipeline_finalization
from Virus_Scan.runtime.api import profile_persistence_state, profile_scoring_state


ROOT = Path(__file__).resolve().parents[1]


def _imports_for(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    return imports


def test_publication_profile_runtime_boundaries_do_not_import_profile_model_internals():
    json_imports = _imports_for(ROOT / "publication" / "json_writer.py")
    finalization_imports = _imports_for(
        ROOT / "publication" / "api" / "pipeline_finalization.py"
    )

    assert "Virus_Scan.models.profiles" not in json_imports
    assert "Virus_Scan.models.profiles" not in finalization_imports
    assert "Virus_Scan.runtime.profile_persistence_state" not in json_imports
    assert "Virus_Scan.runtime.profile_scoring_state" not in finalization_imports
    assert "Virus_Scan.runtime.api" not in json_imports
    assert "Virus_Scan.runtime.api" in finalization_imports


def test_publication_finalization_clears_runtime_owned_profile_scoring_snapshot():
    state = profile_scoring_state()
    state.freeze({"renpy": {"count": 1, "tags": ["clean"]}})

    assert state.is_frozen() is True
    assert state.snapshot() == {"renpy": {"count": 1, "tags": ["clean"]}}

    pipeline_finalization.clear_profile_scoring_snapshot()

    assert state.is_frozen() is False
    assert state.snapshot() == {}


def test_final_json_reads_profile_corruption_snapshot_from_runtime_owner(tmp_path):
    state = profile_persistence_state()
    state.bind_profiles_dir(str(tmp_path))
    event = {
        "engine": "renpy",
        "profile_corruption_reason": "invalid profile schema_version",
        "scan_continued": True,
    }
    state.record_profile_corruption_event(event)

    context = json_writer.compact_success_context(
        {
            "file": "game/script.rpy",
            "classification": "benign",
            "score": 0,
            "tags": ["renpy_script"],
            "scheduler_mode": "serial",
        }
    )

    assert tuple(context["profile_events"]) == state.profile_corruption_events_snapshot()
    assert dict(context["profile_events"][0])["profile_corruption_reason"] == (
        "invalid profile schema_version"
    )
