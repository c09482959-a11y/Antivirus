from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners import pickle_scan
from Virus_Scan.scanners.pickle import escalation, global_references, literals, scanner
from Virus_Scan.scanners.pickle.opcode_analysis import analyze_pickle_opcode_graph
from Virus_Scan.scanners.ci.suppressed_failure_audit import validate_suppressed_failure_manifest


def _function_lengths(path: str) -> dict[str, int]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    lengths: dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            end_lineno = node.end_lineno if node.end_lineno is not None else node.lineno
            lengths[node.name] = end_lineno - node.lineno + 1
    return lengths


def test_pickle_literal_and_global_helpers_have_bounded_ownership():
    assert callable(global_references._pickle_canonical_global)
    assert callable(global_references._pickle_is_dangerous_callable_global)
    assert callable(literals._pickle_arg_to_bytes)
    assert callable(literals._pickle_failure_record)
    assert not hasattr(pickle_scan, "_pickle_canonical_global")
    assert not hasattr(pickle_scan, "_pickle_is_dangerous_callable_global")
    assert not hasattr(pickle_scan, "_pickle_arg_to_bytes")
    assert not hasattr(pickle_scan, "_pickle_failure_record")
    assert scanner.pickle_fragment_decode_records_from_analysis is literals.pickle_fragment_decode_records_from_analysis


def test_pickle_fast_escalation_prefilter_is_decomposed_and_behavior_preserved(tmp_path):
    lengths = _function_lengths("Virus_Scan/scanners/pickle/escalation.py")
    assert lengths["pickle_fast_escalation_prefilter"] <= 75

    sample = tmp_path / "sample.rpyc"
    sample.write_bytes(b"\x80\x04}.")
    result = escalation.pickle_fast_escalation_prefilter(sample)
    assert result["force_full"] is True
    assert "pickle_fast_protocol_hint" in result["tags"]


def test_pickle_opcode_analysis_uses_bounded_literal_and_global_modules():
    source = read_python_file(Path("Virus_Scan/scanners/pickle/opcode_analysis.py"))
    assert "from Virus_Scan.scanners.pickle.literals import" in source
    assert "from Virus_Scan.scanners.pickle.global_references import" in source
    summary = analyze_pickle_opcode_graph(b"cos\nsystem\n(S'cmd.exe'\ntR.")
    assert summary["has_exec_chain"] is True
    assert "os.system" in summary["dangerous_globals"]


def test_stage862_suppressed_failure_manifest_stays_classified():
    report = validate_suppressed_failure_manifest(Path("."))
    assert report["unclassified"] == []
    assert report["stale_manifest"] == []
    assert report["count_mismatches"] == []
