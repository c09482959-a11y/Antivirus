from __future__ import annotations

import ast
from pathlib import Path

import Virus_Scan.models.api as model_api
from Virus_Scan.models import profiles, replay_economics
from Virus_Scan.models.replay import payload as replay_payload
from Virus_Scan.models.api import profile_learning_contracts, replay_economics_contracts
from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES

REPO = Path(__file__).resolve().parents[2]


def _imports_from(path: str) -> set[str]:
    root = REPO / path
    source_paths = sorted(root.glob("*.py")) if root.is_dir() else [root]
    imports: set[str] = set()
    for source_path in source_paths:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
    return imports


def test_profile_learning_contract_is_public_model_api() -> None:
    assert "profile_learning_contracts" in model_api.__all__
    assert "Virus_Scan.models.api.profile_learning_contracts" in MODEL_BOOTSTRAP_MODULE_NAMES
    assert "replay_economics_contracts" in model_api.__all__
    assert "Virus_Scan.models.api.replay_economics_contracts" in MODEL_BOOTSTRAP_MODULE_NAMES


def test_replay_uses_profile_learning_public_contract_not_profile_impl() -> None:
    imports = _imports_from("Virus_Scan/models/replay")

    assert "Virus_Scan.models.profiles" not in imports
    assert "Virus_Scan.models.replay_economics" not in imports
    assert "Virus_Scan.models.api.profile_learning_contracts" in imports
    assert "Virus_Scan.models.api.replay_economics_contracts" in imports


def test_profile_learning_contract_preserves_profile_owner_behaviour() -> None:
    assert profile_learning_contracts.DEFAULT_ENGINES == tuple(profiles.DEFAULT_ENGINES)
    assert profile_learning_contracts.learning_verdict_is_clean("clean") == profiles.learning_verdict_is_clean("clean")
    assert profile_learning_contracts.learning_verdict_is_clean("suspicious") == profiles.learning_verdict_is_clean(
        "suspicious"
    )
    assert profile_learning_contracts.canonical_behavior_flow_from_sources(raw_tags=["network", "execute"]) == profiles.canonical_behavior_flow_from_sources(
        raw_tags=["network", "execute"]
    )
    assert replay_payload.canonical_behavior_flow_from_sources is profile_learning_contracts.canonical_behavior_flow_from_sources


def test_replay_economics_contract_preserves_canonical_owner_behaviour() -> None:
    result = {"score": 12.0, "tags": ["benign"], "explanation": {}}

    assert replay_economics_contracts.replay_should_retain(result) == replay_economics.replay_should_retain(result)
    assert replay_economics_contracts.replay_compress_metadata({"runtime": {"ok": True}}) == replay_economics.replay_compress_metadata({"runtime": {"ok": True}})
