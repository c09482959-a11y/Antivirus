from pathlib import Path


import Virus_Scan.scanners.text as text
from Virus_Scan.detection.enrichment.pe_analysis.bytecode import scan_bytecode_file

def test_text_scanner_context_validation_direct_import_does_not_require_bootstrap():
    assert hasattr(text, 'BROAD_UNVALIDATED_TAGS')
    # This used to log NameError: BROAD_UNVALIDATED_TAGS is not defined when invoked directly.
    assert text.validate_high_risk_tag('network_activity', 'plain text without concrete network execution') is False


def test_detection_bytecode_pickle_direct_import_does_not_require_injected_global(tmp_path):
    p = tmp_path / 'script.rpyc'
    p.write_bytes(b'RENPY RPC2\x00cos\nsystem\n')
    tags = scan_bytecode_file(str(p), finalize=False)
    assert {'pickle_dangerous_global', 'pickle_callable_reference', 'script_execution', 'process_exec'} <= set(tags)
    assert 'pickle_opcode_execution' not in tags
    assert 'renpy_pickle_exec' not in tags
