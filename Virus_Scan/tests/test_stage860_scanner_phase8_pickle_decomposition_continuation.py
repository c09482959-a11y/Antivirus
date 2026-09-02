from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scanners import pickle_scan
from Virus_Scan.scanners.ci.payload_authority_audit import audit_payload_authority
from Virus_Scan.scanners.ci.suppressed_failure_audit import validate_suppressed_failure_manifest
from Virus_Scan.scanners.pickle import embedded_payloads, opcode_analysis, rpa_views, rpyc_views



def test_phase8_pickle_opcode_and_payload_authority_are_bounded_modules():
    assert pickle_scan.analyze_pickle_opcode_graph is opcode_analysis.analyze_pickle_opcode_graph
    assert pickle_scan.pickle_fragment_decode_records_from_analysis is opcode_analysis.pickle_fragment_decode_records_from_analysis
    assert callable(embedded_payloads._iter_pickle_payload_records)
    assert callable(embedded_payloads._iter_raw_compressed_payload_records)
    assert callable(rpyc_views._iter_rpyc_pickle_byte_views)
    assert callable(rpa_views._iter_renpy_rpa_members)
    assert not hasattr(pickle_scan, "_iter_pickle_payload_records")
    assert not hasattr(pickle_scan, "_iter_raw_compressed_payload_records")
    assert not hasattr(pickle_scan, "_iter_rpyc_pickle_byte_views")
    assert not hasattr(pickle_scan, "_iter_renpy_rpa_members")


def test_phase8_pickle_payload_authority_and_suppressed_manifest_are_clean():
    payload_audit = audit_payload_authority(Path('.'))
    assert payload_audit.ok is True
    suppressed = validate_suppressed_failure_manifest(Path('.'))
    assert suppressed['unclassified'] == []
    assert suppressed['stale_manifest'] == []
    assert suppressed['count_mismatches'] == []


def test_phase8_pickle_scan_no_longer_owns_oversized_opcode_or_renpy_helpers():
    pickle_scan_source = read_python_file(Path('Virus_Scan/scanners/pickle_scan.py'))
    assert 'def analyze_pickle_opcode_graph' not in pickle_scan_source
    assert 'def _iter_pickle_payload_records' not in pickle_scan_source
    assert 'def _iter_rpyc_pickle_byte_views' not in pickle_scan_source
    assert 'def _safe_load_rpa_index' not in pickle_scan_source
    assert len(pickle_scan_source.splitlines()) < 750
