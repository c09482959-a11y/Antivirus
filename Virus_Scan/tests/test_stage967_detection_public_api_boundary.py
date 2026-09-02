from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.detection.api import public_contracts
from Virus_Scan.detection.api import runner


def _python_files(root: Path):
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _private_detection_import_findings(root: Path):
    findings = []
    for path in _python_files(root):
        rel = path.as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("Virus_Scan.detection"):
                if not node.module.startswith("Virus_Scan.detection.api"):
                    findings.append((rel, node.lineno, node.module))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("Virus_Scan.detection") and not alias.name.startswith("Virus_Scan.detection.api"):
                        findings.append((rel, node.lineno, alias.name))
    return findings


def test_scheduler_and_reporting_enter_detection_through_public_api_only():
    findings = []
    findings.extend(_private_detection_import_findings(Path("Virus_Scan/scheduler")))
    findings.extend(_private_detection_import_findings(Path("Virus_Scan/reporting")))

    assert findings == []


def test_scanners_do_not_import_detection_domain():
    findings = []
    for path in _python_files(Path("Virus_Scan/scanners")):
        rel = path.as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("Virus_Scan.detection"):
                findings.append((rel, node.lineno, node.module))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("Virus_Scan.detection"):
                        findings.append((rel, node.lineno, alias.name))

    assert findings == []


def test_detection_imports_scanners_through_public_api_only():
    findings = []
    for path in _python_files(Path("Virus_Scan/detection")):
        rel = path.as_posix()
        if rel.startswith("Virus_Scan/detection/api/"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("Virus_Scan.scanners"):
                if not node.module.startswith("Virus_Scan.scanners.api"):
                    findings.append((rel, node.lineno, node.module))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("Virus_Scan.scanners") and not alias.name.startswith("Virus_Scan.scanners.api"):
                        findings.append((rel, node.lineno, alias.name))

    assert findings == []


def test_detection_public_api_exports_scheduler_reporting_contracts():
    assert callable(runner.analyze_file_full_observe_only)
    assert callable(runner.strict_fast_prefilter)
    required_contracts = {
        "STRICT_FAST_PREFILTER_TAG_MAP",
        "contextual_dangerous_anchor_hits",
        "contextual_tag_scan",
        "decoded_payload_tags",
        "explicit_missed_family_tag_scan",
        "finalize_tag_evidence_generation",
        "micro_stage_collect",
        "probabilistic_evidence_summary",
        "remember_scan_evidence",
        "scan_dotnet_file",
        "staged_enrichment_score",
        "umige_js_execution_model_tags",
    }

    assert required_contracts <= set(public_contracts.__all__)
