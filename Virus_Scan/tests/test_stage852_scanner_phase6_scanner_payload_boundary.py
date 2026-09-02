import ast
from pathlib import Path


def test_scanner_modules_do_not_import_detection_payload_decoders():
    findings = []
    for path in Path("Virus_Scan/scanners").rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            module = getattr(node, "module", "") or ""
            if isinstance(node, ast.ImportFrom) and module.startswith("Virus_Scan.detection.enrichment.strings.contextual.decoded_payloads"):
                findings.append((str(path), node.lineno, module))
            if isinstance(node, ast.ImportFrom) and module.startswith("Virus_Scan.detection.evidence.payload_decode"):
                findings.append((str(path), node.lineno, module))
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(("Virus_Scan.detection.evidence.payload_decode", "Virus_Scan.detection.enrichment.strings.contextual.decoded_payloads")):
                        findings.append((str(path), node.lineno, alias.name))
    assert findings == []
