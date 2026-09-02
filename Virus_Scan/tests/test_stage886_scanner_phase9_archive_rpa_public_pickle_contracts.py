from pathlib import Path
import ast

from Virus_Scan.scanners.archives import rpa_member_behavior
from Virus_Scan.scanners.api import pickle_contracts
from Virus_Scan.scanners.pickle import rpa_views, rpyc_views


def test_archive_rpa_member_behavior_uses_public_pickle_contracts():
    assert rpa_member_behavior.iter_pickle_payload_records is pickle_contracts.iter_pickle_payload_records
    assert rpa_member_behavior.iter_renpy_rpa_members is pickle_contracts.iter_renpy_rpa_members
    assert rpa_member_behavior.iter_rpyc_pickle_byte_views is pickle_contracts.iter_rpyc_pickle_byte_views


def test_archive_modules_do_not_import_pickle_implementation_modules():
    root = Path("Virus_Scan/scanners/archives")
    findings = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            module = node.module or ""
            if module.startswith("Virus_Scan.scanners.pickle"):
                findings.append((str(path), module, tuple(alias.name for alias in node.names), node.lineno))
    assert findings == []


def test_public_rpa_view_contract_preserves_empty_input_behavior():
    assert list(rpa_views.iter_renpy_rpa_members(b"not an rpa", path="sample.rpa") or []) == []
    assert list(rpyc_views.iter_rpyc_pickle_byte_views(b"not pickle", path="sample.rpyc") or [])
    assert list(pickle_contracts.iter_pickle_payload_records(b"not pickle") or [])
