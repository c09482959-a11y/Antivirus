from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import from_imported_names, virus_scan_python_files


def test_stage1546_production_code_does_not_import_hybrid_graph_alias() -> None:
    offenders = []
    for path in virus_scan_python_files():
        for lineno, imported_name in from_imported_names(path, "Virus_Scan.runtime.graph_state"):
            if imported_name == "HYBRID_GRAPH":
                offenders.append(f"{path}:{lineno}:HYBRID_GRAPH")
    assert offenders == []
