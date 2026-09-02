from pathlib import Path
import ast

from Virus_Scan.scanners.api import payload_contracts
from Virus_Scan.scanners.archives import payloads, rpa_member_behavior


def test_archive_modules_use_public_payload_api_contracts():
    assert payloads.decoded_payload_behavior_tags is payload_contracts.decoded_payload_behavior_tags
    assert payloads.decoded_payload_tags is payload_contracts.decoded_payload_tags
    assert payloads.embedded_payload_records_from_bytes is payload_contracts.embedded_payload_records_from_bytes
    assert rpa_member_behavior.embedded_payload_records_from_bytes is payload_contracts.embedded_payload_records_from_bytes


def test_archive_package_has_no_direct_payload_decode_implementation_imports():
    findings = []
    for path in sorted(Path("Virus_Scan/scanners/archives").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "") == "Virus_Scan.scanners.payload_decode":
                findings.append((str(path), node.module, tuple(alias.name for alias in node.names), node.lineno))
    assert findings == []


def test_public_payload_contract_exposes_archive_required_payload_views():
    tags = payload_contracts.decoded_payload_tags("powershell -enc SQBFAFgA", path="member.txt", finalize=False)
    assert isinstance(tags, list)
    assert isinstance(payload_contracts.decoded_payload_behavior_tags({}, []), list)
    records = payload_contracts.embedded_payload_records_from_bytes(b"not encoded payload", encoding_hint="archive_member")
    assert isinstance(records, list)
