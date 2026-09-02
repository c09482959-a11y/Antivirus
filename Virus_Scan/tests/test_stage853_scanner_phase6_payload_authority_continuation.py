from Virus_Scan.tests.support.static_inventory import read_python_file

import base64

from pathlib import Path

from Virus_Scan.detection.chains.execution import pickle_opcode_graph
from Virus_Scan.detection.correlation.multi_signal.cluster_feature_tags import decode_feature_tags_for_cluster
from Virus_Scan.detection.contracts.string_extraction import build_extraction_view
from Virus_Scan.scanners.api import payload_contracts
from Virus_Scan.scanners.ci.payload_authority_audit import audit_payload_authority



def test_phase6_payload_authority_audit_is_clean():
    result = audit_payload_authority(".")
    assert result.ok is True
    assert result.findings == ()
    assert result.deleted_duplicate_files_absent is True


def test_detection_pickle_payload_duplicates_are_deleted():
    assert not Path("Virus_Scan/detection/evidence/pickle_payloads.py").exists()
    assert not Path("Virus_Scan/detection/evidence/pickle_fragments.py").exists()


def test_detection_pickle_path_no_longer_imports_scanner_fragment_decoders():
    source = read_python_file(Path("Virus_Scan/detection/chains/execution/pickle_opcode_graph.py"))
    assert "Virus_Scan.scanners" not in source
    assert "pickle_fragment_decode_records_from_analysis" not in source
    binary_source = read_python_file(Path("Virus_Scan/detection/enrichment/pe_analysis/binary_static.py"))
    assert "Virus_Scan.scanners" not in binary_source



def test_detection_feature_and_string_extraction_consume_scanner_payload_observations():

    encoded = base64.b64encode(b"powershell cmd.exe http://example.test").decode("ascii")
    decoded_records = payload_contracts.safe_decode_payloads(encoded)
    features = set(decode_feature_tags_for_cluster(encoded, decoded_payloads=decoded_records))
    view = build_extraction_view(encoded, decoded_payloads=decoded_records)
    assert "cluster_decoded_base64" in features
    assert "powershell" in view.lower()
    assert decoded_records
