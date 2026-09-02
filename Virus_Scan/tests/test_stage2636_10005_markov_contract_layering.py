"""Stage2636 Markov request ownership and layer-boundary regressions."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.contracts.markov_learning import MarkovUpdateRequest


def _imports(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
    return tuple(modules)


def test_stage2636_markov_runtime_request_contract_is_data_only() -> None:
    contract_path = Path(__file__).resolve().parents[1] / "contracts" / "markov_learning.py"

    assert not any(module.startswith("Virus_Scan.models") for module in _imports(contract_path))
    assert not hasattr(MarkovUpdateRequest, "from_learning_decision")


def test_stage2636_markov_learning_owner_performs_decision_conversion() -> None:
    learning_path = Path(__file__).resolve().parents[1] / "models" / "markov" / "learning.py"
    source = learning_path.read_text(encoding="utf-8")

    assert "def _markov_update_request(" in source
    assert "LearningDecision" in source
    assert "commit_markov_update_request(request)" in source
