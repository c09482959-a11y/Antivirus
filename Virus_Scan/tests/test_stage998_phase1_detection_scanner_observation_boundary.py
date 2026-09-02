from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path
import ast
import base64

from Virus_Scan.detection.api.chains_contracts import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.detection.contracts.string_extraction import build_extraction_view
from Virus_Scan.detection.enrichment.strings.contextual.decoded_payloads import decoded_payload_tags
from Virus_Scan.detection.enrichment.strings.contextual.scan import ContextualTagScanRequest, contextual_tag_scan
from Virus_Scan.detection.correlation.multi_signal.cluster_feature_tags import decode_feature_tags_for_cluster
from Virus_Scan.detection.correlation.temporal.behavior_timeline import build_behavior_timeline
from Virus_Scan.scanners.api import payload_contracts



def _imports_from(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            yield node.module
        elif isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name


def test_detection_tree_has_no_scanner_imports_after_observation_boundary():
    findings = []
    for path in sorted(Path("Virus_Scan/detection").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        for module in _imports_from(path):
            if module.startswith("Virus_Scan.scanners"):
                findings.append((path.as_posix(), module))
    assert findings == []


def test_detection_consumes_scanner_observed_decoded_payload_records():
    encoded = base64.b64encode(b'powershell cmd.exe http://example.test CreateProcessA("cmd.exe")').decode("ascii")
    records = payload_contracts.safe_decode_payloads(encoded)
    assert records

    view = build_extraction_view(encoded, decoded_payloads=records)
    assert "powershell" in view.lower()

    tags = set(decoded_payload_tags("", path="payload.txt", finalize=False, decoded_payloads=records))
    assert {"payload_decode_confirmed", "network_download", "process_exec"} <= tags
    assert "decoded_base64_execution_chain" not in tags
    assert "decoded_base64_network_chain" not in tags
    chain_evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(sorted(tags))))
    assert any(
        decision.candidate.chain_id == "anchor:decoded_network_execution"
        and decision.status == "candidate"
        for decision in chain_evidence.decisions
    )

    contextual = set(contextual_tag_scan(ContextualTagScanRequest(encoded, path="payload.txt", finalize=False, decoded_payloads=records)))
    assert "process_exec" in contextual or "powershell_exec" in contextual

    features = set(decode_feature_tags_for_cluster(encoded, decoded_payloads=records))
    assert "cluster_decoded_base64" in features
    assert "cluster_decoded_behavior_exec" in features

    timeline, ordered = build_behavior_timeline(encoded, decoded_payloads=records)
    assert any(event.get("kind") == "decoded_api" for event in timeline)
    assert "process_exec" in ordered
    assert "powershell_exec" in ordered


def test_scheduler_raw_policy_uses_scanner_decode_contract_not_detection_decoder():
    source = read_python_file(Path("Virus_Scan/scheduler/context/inmemory_raw_policy_dependencies.py"))
    assert "from Virus_Scan.scanners.api.payload_contracts import decoded_payload_tags" in source
    assert "from Virus_Scan.detection.api.public_contracts import decoded_payload_tags" not in source
