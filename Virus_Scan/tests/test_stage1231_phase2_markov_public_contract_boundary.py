import ast
from pathlib import Path

import Virus_Scan.models.api as model_api
from Virus_Scan.models import markov
from Virus_Scan.models.api import markov_contracts
from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES


def _import_modules(path: str) -> set[str]:
    paths = sorted(Path(path).glob("*.py")) if Path(path).is_dir() else [Path(path)]
    modules: set[str] = set()
    for source_path in paths:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                modules.add(str(node.module or ""))
            elif isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
    return modules


def test_markov_contract_is_public_model_api_and_bootstrap_registered():
    assert "markov_contracts" in model_api.__all__
    assert "Virus_Scan.models.api.markov_contracts" in MODEL_BOOTSTRAP_MODULE_NAMES


def test_model_subdomains_use_markov_public_contract_only_when_they_consume_markov():
    expected_contract_consumers = {
        "Virus_Scan/models/graph": True,
        "Virus_Scan/models/temporal": True,
        "Virus_Scan/models/profiles": True,
        "Virus_Scan/models/replay": False,
    }
    for path, consumes_markov in expected_contract_consumers.items():
        imports = _import_modules(path)
        assert "Virus_Scan.models.markov" not in imports
        assert "Virus_Scan.models.markov.api" not in imports
        assert ("Virus_Scan.models.api.markov_contracts" in imports) is consumes_markov


def test_markov_public_contract_preserves_canonical_owner_behavior():
    flow = ("network", "decode", "execute")
    assert markov_contracts.canonical_behavior_flow(flow) == markov.canonical_behavior_flow(flow)
    assert markov_contracts.compute_markov_features("static", flow, "result") == markov.compute_markov_features(
        "static", flow, "result"
    )
    assert markov_contracts.markov_pair_probability("network", "execute") == markov.markov_pair_probability(
        "network", "execute"
    )
