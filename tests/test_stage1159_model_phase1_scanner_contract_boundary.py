from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path



def _imports_for(path: str):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
    return tuple(imports)


def test_model_modules_do_not_import_scanner_api_contracts_for_profile_or_cluster_features():
    for path in ("Virus_Scan/models/profiles/api.py",):
        imports = _imports_for(path)
        assert not any(name.startswith("Virus_Scan.scanners.api") for name in imports), (path, imports)
    for path in sorted(Path("Virus_Scan/models/clustering").glob("*.py")):
        imports = _imports_for(str(path))
        assert not any(name.startswith("Virus_Scan.scanners.api") for name in imports), (path, imports)


def test_profile_baseline_hard_proof_uses_neutral_contract_not_core_or_scanner_contracts():
    source = read_python_file(Path("Virus_Scan/models/profiles/baseline.py"))
    assert "Virus_Scan.contracts.library_baseline" in source
    assert "library_baseline_has_hard_proof" in source
    assert "Virus_Scan.core.library_baseline" not in source
    assert "Virus_Scan.scanners.api.text_contracts" not in source


def test_clustering_uses_neutral_tag_entropy_and_no_payload_decoder_extraction():
    source = "\n".join(path.read_text(encoding="utf-8") for path in sorted(Path("Virus_Scan/models/clustering").glob("*.py")))
    assert "from Virus_Scan.utils.entropy import tag_entropy" in source
    assert "safe_decode_payloads" not in source


def test_strict_prefilter_terminal_failure_is_explicit_not_falsey_clean_fallback():
    source = read_python_file(Path("Virus_Scan/detection/enrichment/prefilter/scan.py"))
    assert "class _FalsePrefilterFailure" not in source
    assert "def __bool__" not in source
    assert "terminal_status is TERMINAL_PREFILTER_FAILED" in source
