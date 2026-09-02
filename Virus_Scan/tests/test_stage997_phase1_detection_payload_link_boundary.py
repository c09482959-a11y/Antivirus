from Virus_Scan.tests.support.static_inventory import read_python_file

import base64
from pathlib import Path

from Virus_Scan.scanners.api import payload_contracts

from Virus_Scan.detection.enrichment.strings.contextual.scan import ContextualTagScanRequest, contextual_tag_scan
from Virus_Scan.detection.enrichment.strings.contextual.js_execution_model import umige_js_execution_model_tags
from Virus_Scan.detection.evidence.relationships.evidence_links import umige_evidence_link_tags
from Virus_Scan.detection.correlation.temporal.behavior_timeline import build_behavior_timeline



def test_evidence_links_no_longer_import_scanner_payload_contracts():
    source = read_python_file(Path("Virus_Scan/detection/evidence/relationships/evidence_links.py"))
    assert "Virus_Scan.scanners" not in source
    assert "safe_decode_payloads" not in source


def test_contextual_scan_still_links_decoded_payload_behavior_through_scanner_observation():
    encoded = base64.b64encode(b"powershell cmd.exe http://example.test").decode("ascii")
    decoded_records = payload_contracts.safe_decode_payloads(encoded)
    tags = set(contextual_tag_scan(ContextualTagScanRequest(encoded, path="payload.txt", finalize=False, decoded_payloads=decoded_records)))
    assert "evidence_link:decoded_payload_to_execution" in tags
    assert "evidence_link:decoded_payload_to_network" in tags
    assert "evidence_link:decoded_payload_execution_network_correlation" in tags


def test_js_execution_model_no_longer_imports_scanner_payload_contracts():
    source = read_python_file(Path("Virus_Scan/detection/enrichment/strings/contextual/js_execution_model.py"))
    assert "Virus_Scan.scanners" not in source
    assert "safe_decode_payloads" not in source


def test_js_execution_model_links_already_observed_decoded_payload_text():
    tags = set(umige_js_execution_model_tags(
        "eval(atob(x)); payload_decode_candidate decoded_payload_rescanned powershell cmd.exe http://example.test",
        path="plugins.js",
        finalize=False,
    ))
    assert "js_decode_execute_chain" not in tags
    assert "js_decoded_payload_execution_candidate" in tags
    assert "payload_decode_confirmed" in tags


def test_evidence_link_direct_view_semantics_without_payload_decoding():
    tags = set(umige_evidence_link_tags("base64 powershell cmd.exe http://example.test"))
    assert "payload_execution" in tags
    assert "network_activity" in tags
    assert "evidence_link:decode_observed" in tags


def test_cluster_and_timeline_no_longer_import_scanner_payload_contracts():
    cluster_source = read_python_file(Path("Virus_Scan/detection/correlation/multi_signal/cluster_feature_tags.py"))
    timeline_source = read_python_file(Path("Virus_Scan/detection/correlation/temporal/behavior_timeline.py"))
    assert "Virus_Scan.scanners" not in cluster_source
    assert "Virus_Scan.scanners" not in timeline_source


def test_timeline_still_observes_decoded_api_events_from_scanner_observation():
    encoded = base64.b64encode(b'CreateProcessA("cmd.exe")').decode("ascii")
    decoded_records = payload_contracts.safe_decode_payloads(encoded)
    timeline, ordered = build_behavior_timeline(encoded, decoded_payloads=decoded_records)
    decoded_events = [event for event in timeline if event.get("kind") == "decoded_api"]
    assert decoded_events
    assert "process_exec" in ordered
