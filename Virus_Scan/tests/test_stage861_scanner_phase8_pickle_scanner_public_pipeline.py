from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path

from Virus_Scan.scanners import pickle_scan
from Virus_Scan.scanners.api import pickle_contracts
from Virus_Scan.scanners.pickle import embedded_payloads, escalation, graph_tags, opcode_analysis, scanner, source_detection



def test_phase8_pickle_scan_facade_has_no_owned_implementation_functions():
    source = read_python_file(Path('Virus_Scan/scanners/pickle_scan.py'))
    tree = ast.parse(source)
    assert [node.name for node in tree.body if isinstance(node, ast.FunctionDef)] == []
    assert len(source.splitlines()) < 120


def test_phase8_pickle_public_pipeline_is_canonical_scanner_module():
    assert scanner.analyze_pickle_opcode_graph is opcode_analysis.analyze_pickle_opcode_graph
    assert scanner.pickle_fragment_decode_records_from_analysis is opcode_analysis.pickle_fragment_decode_records_from_analysis
    assert scanner.pickle_embedded_payload_tags is embedded_payloads.pickle_embedded_payload_tags
    assert scanner.pickle_fast_escalation_prefilter is escalation.pickle_fast_escalation_prefilter
    assert scanner.detect_python_pickle_opcode_exec is graph_tags.detect_python_pickle_opcode_exec
    assert scanner.renpy_source_pickle_injection_tags is source_detection.renpy_source_pickle_injection_tags
    assert pickle_contracts.pickle_embedded_payload_tags is scanner.pickle_embedded_payload_tags
    assert pickle_scan.pickle_fast_escalation_prefilter is scanner.pickle_fast_escalation_prefilter


def test_phase8_scanner_production_code_no_longer_imports_pickle_scan_internals():
    offenders = []
    for path in sorted(Path('Virus_Scan').rglob('*.py')):
        if '/tests/' in path.as_posix() or path.as_posix().endswith('pickle_scan.py'):
            continue
        text = path.read_text(encoding='utf-8', errors='ignore')
        if 'Virus_Scan.scanners.pickle_scan' in text:
            offenders.append(path.as_posix())
    assert offenders == []
