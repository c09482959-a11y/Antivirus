from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models.api import replay_learning
from Virus_Scan.models.replay import api as replay_api
from Virus_Scan.publication.api import pipeline_finalization


def test_stage1457_replay_api_has_no_private_delegate_attributes() -> None:
    leaked = [name for name in dir(replay_api) if name.startswith("_") and not name.startswith("__")]
    assert leaked == []


def test_stage1457_replay_public_contracts_use_public_owner_modules() -> None:
    assert replay_learning.replay_model_api is replay_api
    assert pipeline_finalization.model_replay_learning_contract is replay_learning


def test_stage1457_replay_public_contract_sources_do_not_private_alias_delegates() -> None:
    repo = Path(__file__).resolve().parents[1]
    offenders: list[str] = []
    for relative in (
        "models/replay/api.py",
        "models/api/replay_learning.py",
        "publication/api/pipeline_finalization.py",
    ):
        path = repo / relative
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    exposed = alias.asname or alias.name
                    if exposed.startswith("_"):
                        offenders.append(f"{relative}:{node.lineno}:{exposed}")
    assert offenders == []
