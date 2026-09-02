from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners import pickle_scan
from Virus_Scan.scanners.ci.policy_table_config_audit import scan_policy_table_config_findings
from Virus_Scan.scanners.ci.suppressed_failure_audit import validate_suppressed_failure_manifest
from Virus_Scan.scanners.pickle import (
    embedded_payloads,
    graph_tags,
    opcode_analysis,
    opcode_state,
    opcode_history,
    opcode_memo,
    opcode_reduce,
    opcode_sets,
    opcode_stack,
    opcode_summary,
    payload_records,
    payload_tags,
    rpa_views,
    rpyc_views,
    source_detection,
    text_evidence,
)


def _module_functions(path: str) -> dict[str, int]:
    tree = ast.parse(Path(path).read_text(encoding='utf-8'))
    lengths: dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            end_lineno = node.end_lineno if node.end_lineno is not None else node.lineno
            lengths[node.name] = end_lineno - node.lineno + 1
    return lengths


def test_pickle_view_and_source_ownership_is_bounded_and_canonical():
    assert callable(rpa_views._iter_renpy_rpa_members)
    assert callable(rpa_views._safe_load_rpa_index)
    assert callable(rpyc_views._iter_rpyc_pickle_byte_views)
    assert callable(rpyc_views._pickle_container_magic_present)
    assert not hasattr(pickle_scan, "_iter_renpy_rpa_members")
    assert not hasattr(pickle_scan, "_safe_load_rpa_index")
    assert not hasattr(pickle_scan, "_iter_rpyc_pickle_byte_views")
    assert not hasattr(pickle_scan, "_pickle_container_magic_present")
    assert pickle_scan.renpy_source_pickle_injection_tags is source_detection.renpy_source_pickle_injection_tags


def test_pickle_payload_and_evidence_projection_ownership_is_bounded_and_canonical():
    assert callable(payload_records._iter_pickle_payload_records)
    assert callable(payload_records._iter_raw_compressed_payload_records)
    assert callable(payload_tags._pickle_decoded_payload_tags)
    assert not hasattr(pickle_scan, "_iter_pickle_payload_records")
    assert not hasattr(pickle_scan, "_iter_raw_compressed_payload_records")
    assert not hasattr(pickle_scan, "_pickle_decoded_payload_tags")
    assert embedded_payloads._iter_pickle_payload_records is payload_records._iter_pickle_payload_records
    assert embedded_payloads._pickle_decoded_payload_tags is payload_tags._pickle_decoded_payload_tags
    assert callable(text_evidence._pickle_bytes_to_text_views)
    assert not hasattr(pickle_scan, "_pickle_bytes_to_text_views")
    assert pickle_scan.pickle_opcode_graph_tags is graph_tags.pickle_opcode_graph_tags


def test_pickle_opcode_analysis_uses_bounded_state_helpers_and_preserves_behavior():
    lengths = _module_functions('Virus_Scan/scanners/pickle/opcode_analysis.py')
    assert lengths['analyze_pickle_opcode_graph'] <= 75
    assert lengths['_analyze_single_pickle_stream'] <= 75
    for module_path in (
        'Virus_Scan/scanners/pickle/opcode_history.py',
        'Virus_Scan/scanners/pickle/opcode_memo.py',
        'Virus_Scan/scanners/pickle/opcode_reduce.py',
        'Virus_Scan/scanners/pickle/opcode_stack.py',
        'Virus_Scan/scanners/pickle/opcode_summary.py',
    ):
        bounded_lengths = _module_functions(module_path)
        assert bounded_lengths
        assert max(bounded_lengths.values()) <= 75
    state_lengths = _module_functions('Virus_Scan/scanners/pickle/opcode_state.py')
    assert state_lengths == {}
    assert opcode_state.record_opcode_history is opcode_history.record_opcode_history
    assert opcode_state.memoize_stack_value is opcode_memo.memoize_stack_value
    assert opcode_state.append_reduce_chain is opcode_reduce.append_reduce_chain
    assert opcode_state.LITERAL_OPCODES is opcode_sets.LITERAL_OPCODES
    assert opcode_state.append_literal_opcode is opcode_stack.append_literal_opcode
    assert opcode_state.dedupe_summary_lists is opcode_summary.dedupe_summary_lists
    summary = opcode_analysis.analyze_pickle_opcode_graph(b"cos\nsystem\n(S'cmd.exe'\ntR.")
    assert summary['has_exec_chain'] is True
    assert 'os.system' in summary['dangerous_globals']


def test_phase8_pickle_decomposition_audits_remain_clean():
    report = validate_suppressed_failure_manifest(Path('.'))
    assert report['unclassified'] == []
    assert report['stale_manifest'] == []
    assert report['count_mismatches'] == []
    assert scan_policy_table_config_findings('Virus_Scan/scanners') == ()
