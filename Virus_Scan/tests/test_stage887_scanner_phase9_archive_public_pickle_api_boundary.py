from pathlib import Path
import ast

from Virus_Scan.scanners.api import pickle_contracts
from Virus_Scan.scanners.archives import payloads, rpa, rpa_member_behavior


def test_archive_rpa_and_payload_modules_use_public_pickle_api_contracts():
    assert payloads.pickle_embedded_payload_tags is pickle_contracts.pickle_embedded_payload_tags
    assert rpa.pickle_embedded_payload_tags is pickle_contracts.pickle_embedded_payload_tags
    assert rpa_member_behavior.iter_pickle_payload_records is pickle_contracts.iter_pickle_payload_records
    assert rpa_member_behavior.iter_renpy_rpa_members is pickle_contracts.iter_renpy_rpa_members
    assert rpa_member_behavior.iter_rpyc_pickle_byte_views is pickle_contracts.iter_rpyc_pickle_byte_views


def test_archive_package_has_no_direct_pickle_implementation_imports():
    findings = []
    for path in sorted(Path("Virus_Scan/scanners/archives").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("Virus_Scan.scanners.pickle"):
                findings.append((str(path), node.module, tuple(alias.name for alias in node.names), node.lineno))
    assert findings == []


def test_public_pickle_contract_exposes_archive_required_pickle_views():
    assert list(pickle_contracts.iter_renpy_rpa_members(b"not an rpa", path="sample.rpa") or []) == []
    assert list(pickle_contracts.iter_rpyc_pickle_byte_views(b"not pickle", path="sample.rpyc") or [])
    assert list(pickle_contracts.iter_pickle_payload_records(b"not pickle") or [])
