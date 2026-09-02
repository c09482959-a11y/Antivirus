import ast
from pathlib import Path

from Virus_Scan.contracts.yara_hits import (
    normalize_yara_hits,
    normalize_yara_rule_name,
    yara_expected_behavior,
)

GRAPH_OWNER_PATHS = tuple(sorted(Path("Virus_Scan/models/graph").glob("*.py")))
MODEL_AND_SCORING_PATHS = (
    Path("Virus_Scan/detection/scoring/adaptive/evidence_projection.py"),
    Path("Virus_Scan/detection/scoring/yara/context_evidence.py"),
)
CLUSTERING_OWNER_PATHS = tuple(sorted(Path("Virus_Scan/models/clustering").glob("*.py")))


def _imports(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
    return tuple(modules)


def test_model_and_scoring_yara_hit_consumers_use_neutral_contract_not_yara_phase_module():
    clustering_imports = set().union(*(_imports(path) for path in CLUSTERING_OWNER_PATHS))
    assert "Virus_Scan.contracts.yara_hits" not in clustering_imports
    assert "Virus_Scan.yara.phase_contracts" not in clustering_imports
    graph_imports = set().union(*(_imports(path) for path in GRAPH_OWNER_PATHS))
    assert "Virus_Scan.contracts.yara_hits" not in graph_imports
    assert "Virus_Scan.yara.phase_contracts" not in graph_imports
    for path in MODEL_AND_SCORING_PATHS:
        imports = _imports(path)
        assert "Virus_Scan.contracts.yara_hits" in imports, (path, imports)
        assert "Virus_Scan.yara.phase_contracts" not in imports, (path, imports)


def test_neutral_yara_hit_contract_preserves_stable_rule_normalization():
    class Hit:
        rule = " Credential Stealer Rule! "

    assert normalize_yara_rule_name({"rule": "Ransom Rule!?"}) == "Ransom_Rule"
    assert normalize_yara_hits([Hit(), {"name": "z rule"}, "z rule"]) == [
        "Credential_Stealer_Rule",
        "z_rule",
    ]
    assert yara_expected_behavior("credential_stealer") == "credential_access"


def test_detection_yara_contract_wrapper_removed_after_call_site_rewrite():
    assert not Path("Virus_Scan/detection/contracts/yara_hits.py").exists()
    for path in Path("Virus_Scan/detection").rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "Virus_Scan.detection.contracts.yara_hits" not in source, path
