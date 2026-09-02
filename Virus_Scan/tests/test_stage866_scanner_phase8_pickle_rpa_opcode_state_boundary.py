from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners import pickle_scan
from Virus_Scan.scanners.ci.suppressed_failure_audit import validate_suppressed_failure_manifest
from Virus_Scan.scanners.pickle import opcode_state, rpa_views
from Virus_Scan.scanners.pickle import opcode_history, opcode_memo, opcode_reduce, opcode_sets, opcode_stack, opcode_summary
from Virus_Scan.scanners.pickle import rpa_index, rpa_member_payloads


def _function_lengths(path: str) -> dict[str, int]:
    tree = ast.parse(Path(path).read_text(encoding='utf-8'))
    lengths: dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            end_lineno = node.end_lineno if node.end_lineno is not None else node.lineno
            lengths[node.name] = end_lineno - node.lineno + 1
    return lengths


def test_rpa_views_is_a_thin_facade_over_index_and_member_owners():
    assert not hasattr(pickle_scan, "_safe_load_rpa_index")
    assert not hasattr(pickle_scan, "_iter_renpy_rpa_members")
    assert rpa_views._safe_load_rpa_index is rpa_index._safe_load_rpa_index
    assert rpa_views._iter_renpy_rpa_members is rpa_member_payloads._iter_renpy_rpa_members
    assert _function_lengths('Virus_Scan/scanners/pickle/rpa_views.py') == {}
    for path in (
        'Virus_Scan/scanners/pickle/rpa_index.py',
        'Virus_Scan/scanners/pickle/rpa_member_payloads.py',
    ):
        lengths = _function_lengths(path)
        assert lengths
        assert max(lengths.values()) <= 40


def test_opcode_state_is_a_thin_facade_over_bounded_opcode_owners():
    assert opcode_state.record_opcode_history is opcode_history.record_opcode_history
    assert opcode_state.memoize_stack_value is opcode_memo.memoize_stack_value
    assert opcode_state.append_reduce_chain is opcode_reduce.append_reduce_chain
    assert opcode_state.LITERAL_OPCODES is opcode_sets.LITERAL_OPCODES
    assert opcode_state.append_literal_opcode is opcode_stack.append_literal_opcode
    assert opcode_state.dedupe_literal_fragments is opcode_summary.dedupe_literal_fragments
    assert _function_lengths('Virus_Scan/scanners/pickle/opcode_state.py') == {}
    for path in (
        'Virus_Scan/scanners/pickle/opcode_history.py',
        'Virus_Scan/scanners/pickle/opcode_memo.py',
        'Virus_Scan/scanners/pickle/opcode_reduce.py',
        'Virus_Scan/scanners/pickle/opcode_stack.py',
        'Virus_Scan/scanners/pickle/opcode_summary.py',
    ):
        lengths = _function_lengths(path)
        assert lengths
        assert max(lengths.values()) <= 40


def test_stage866_suppressed_failure_manifest_remains_clean_after_moves():
    report = validate_suppressed_failure_manifest(Path('.'))
    assert report['unclassified'] == []
    assert report['stale_manifest'] == []
    assert report['count_mismatches'] == []
