from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.scanners.pickle.embedded_payloads import pickle_embedded_payload_tags
from Virus_Scan.scanners.pickle.graph_base import base_opcode_graph_tags
from Virus_Scan.scanners.pickle.rpyc_views import _rpyc_safe_extension, iter_rpyc_pickle_byte_views
from Virus_Scan.scanners.pickle.source_detection import renpy_pickle_path_status, renpy_source_pickle_injection_tags


def _import_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_pickle_path_identity_uses_public_contract_not_private_stage_utils() -> None:
    checked = [
        Path("Virus_Scan/scanners/pickle/embedded_payloads.py"),
        Path("Virus_Scan/scanners/pickle/graph_base.py"),
        Path("Virus_Scan/scanners/pickle/rpyc_views.py"),
        Path("Virus_Scan/scanners/pickle/source_detection.py"),
    ]
    for path in checked:
        modules = _import_modules(path)
        assert "Virus_Scan.utils.stages" not in modules
        assert "Virus_Scan.contracts.path_identity" in modules


def test_pickle_path_identity_preserves_renpy_and_rpa_scope_behavior() -> None:
    assert renpy_pickle_path_status("game/scripts/start.rpy") == "present"
    assert renpy_pickle_path_status("save_data.rpa") == "present"
    assert renpy_pickle_path_status("plain.txt") == "absent"
    assert _rpyc_safe_extension("game/scripts/start.rpyc") == ".rpyc"
    assert _rpyc_safe_extension("archive.rpa") == ".rpa"


def test_pickle_path_identity_preserves_opcode_and_source_tag_projection() -> None:
    source_tags = renpy_source_pickle_injection_tags(
        "pickle.loads(base64.b64decode(data)); os.system('calc')",
        path="game/scripts/start.rpy",
    )
    assert "pickle_source_injection_candidate" in source_tags
    assert "pickle_callable_reference" in source_tags
    assert "process_exec" in source_tags
    assert "renpy_pickle_exec" not in source_tags
    assert "pickle_opcode_execution" not in source_tags
    source_evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(source_tags)))
    assert any(
        item.candidate.chain_id == "probable_payload_execution_chain"
        and item.status == "candidate"
        for item in source_evidence.decisions
    )
    graph_tags = base_opcode_graph_tags(
        {"globals": ["os.system"], "has_stack_global": False, "has_reduce": True, "dangerous_globals": ["os.system"], "reduce_chains": ["os.system"], "has_exec_chain": True},
        path="game/archive.rpa",
    )
    assert "pickle_reduce_opcode" in graph_tags
    assert "pickle_callable_reference" in graph_tags
    assert "pickle_file_load_context" in graph_tags
    assert "rpa_index_pickle_exec" not in graph_tags
    assert "pickle_opcode_execution" not in graph_tags
    graph_evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(graph_tags)))
    assert any(
        item.candidate.chain_id == "anchor:rpa_index_pickle_opcode_execution"
        and item.status == "candidate"
        for item in graph_evidence.decisions
    )


def test_pickle_embedded_and_rpyc_views_still_return_visible_results() -> None:
    views = list(iter_rpyc_pickle_byte_views(b"\x80\x04K*.\n", path="game/scripts/start.rpyc"))
    assert views
    tags = pickle_embedded_payload_tags(b"\x80\x04K*.\n", path="game/scripts/start.rpyc")
    assert isinstance(tags, list)
