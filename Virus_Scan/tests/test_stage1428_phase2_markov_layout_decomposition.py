"""Stage 1428 Phase 2/4 regression tests for Markov package ownership."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import import_modules, python_files_under


from pathlib import Path

from Virus_Scan.models.markov import api as markov_api
from Virus_Scan.models.api import adaptive_signals, markov_contracts
from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES

MARKOV_PACKAGE = Path("Virus_Scan/models/markov")


def _imports_for(path: Path) -> set[str]:
    relative = path.as_posix()
    source_paths = python_files_under(relative) if path.is_dir() else (path,)
    imports: set[str] = set()
    for source_path in source_paths:
        imports.update(import_modules(source_path))
    return imports


def test_stage1428_markov_is_package_not_monolith() -> None:
    assert not Path("Virus_Scan/models/markov.py").exists()
    for name in ("api.py", "flow.py", "probability.py", "features.py", "learning.py", "evidence.py"):
        assert (MARKOV_PACKAGE / name).exists()
    assert all(len(path.read_text(encoding="utf-8").splitlines()) < 260 for path in MARKOV_PACKAGE.glob("*.py"))


def test_stage1428_markov_public_contracts_enter_api_module() -> None:
    assert markov_contracts.canonical_behavior_flow is markov_api.canonical_behavior_flow
    assert adaptive_signals.adaptive_markov_signal('a', 'b', ('x',)) == markov_api.adaptive_markov_signal('a', 'b', ('x',))
    assert "Virus_Scan.models.markov.api" in MODEL_BOOTSTRAP_MODULE_NAMES


def test_stage1428_non_markov_model_subdomains_use_markov_contract_only_when_needed() -> None:
    expected_contract_consumers = {
        Path("Virus_Scan/models/graph"): True,
        Path("Virus_Scan/models/temporal"): True,
        Path("Virus_Scan/models/profiles"): True,
        Path("Virus_Scan/models/replay"): False,
    }
    for path, consumes_markov in expected_contract_consumers.items():
        imports = _imports_for(path)
        assert "Virus_Scan.models.markov" not in imports
        assert "Virus_Scan.models.markov.api" not in imports
        assert ("Virus_Scan.models.api.markov_contracts" in imports) is consumes_markov
