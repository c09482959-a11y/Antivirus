from Virus_Scan.tests.support.static_inventory import parse_python_file, python_files_under, read_python_file

import ast
from pathlib import Path



def test_stage838_no_cross_subdomain_private_scheduler_imports_remain():
    root = Path("Virus_Scan/scheduler").resolve()
    findings = []
    for path in python_files_under("Virus_Scan/scheduler"):
        source = read_python_file(path)
        if "from Virus_Scan.scheduler." not in source:
            continue
        tree = parse_python_file(path)
        source_domain = path.relative_to(root).parts[0]
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            if not node.module.startswith("Virus_Scan.scheduler."):
                continue
            imported_domain = node.module.split(".")[2]
            if imported_domain == source_domain:
                continue
            private_names = [alias.name for alias in node.names if alias.name.startswith("_")]
            if private_names:
                findings.append(f"{path}:{node.lineno} imports {private_names} from {node.module}")
    assert findings == []


def test_stage838_orchestration_uses_queue_public_contracts():
    checked = [
        Path("Virus_Scan/scheduler/orchestration/process_queue_child_mode.py"),
        Path("Virus_Scan/scheduler/orchestration/process_queue_completion.py"),
        Path("Virus_Scan/scheduler/orchestration/process_queue_monitor_recovery.py"),
        Path("Virus_Scan/scheduler/orchestration/process_queue_startup_admission.py"),
    ]
    for path in checked:
        source = path.read_text(encoding="utf-8")
        assert "from Virus_Scan.scheduler.queue." in source
        for line in source.splitlines():
            if line.startswith("from Virus_Scan.scheduler.queue."):
                assert " import _" not in line, f"{path}: {line}"


def test_stage838_shared_final_json_helpers_removed_duplicate_projection_helpers():
    helper = read_python_file(Path("Virus_Scan/scheduler/evidence/final_json_contract_support.py"))
    assert "def scheduler_status_sources" in helper
    assert "def dedupe_scheduler_evidence_records" in helper
    queue_projection = read_python_file(Path("Virus_Scan/scheduler/evidence/final_json_queue_projection.py"))
    assert "def _mapping_from_scheduler_value" not in queue_projection
    assert "def _dedupe_queue_records" not in queue_projection
