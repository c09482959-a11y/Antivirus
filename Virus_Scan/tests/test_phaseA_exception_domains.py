from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path


PHASE_A_ZERO_BROAD = (
    Path("Virus_Scan/core/jsonio.py"),
    Path("Virus_Scan/scheduler/execution/process_queue_runner.py"),
    Path("Virus_Scan/detection/chains/composite/strong_partial.py"),
    Path("Virus_Scan/scanners/pickle_scan.py"),
    Path("Virus_Scan/core/paths.py"),
    Path("Virus_Scan/contracts/env_config.py"),
    Path("Virus_Scan/contracts/file_fingerprint.py"),
    Path("Virus_Scan/contracts/path_identity.py"),
    Path("Virus_Scan/contracts/result_record.py"),
    Path("Virus_Scan/contracts/string_eval.py"),
    Path("Virus_Scan/contracts/work_stage.py"),
)

def test_phase_a_remediated_files_have_no_broad_or_bare_exception_handlers():
    for path in PHASE_A_ZERO_BROAD:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                caught = "bare" if node.type is None else ast.unparse(node.type)
                if caught in {"bare", "Exception", "BaseException"}:
                    offenders.append((node.lineno, caught))
        assert offenders == [], f"{path}: {offenders}"

def test_phase_a_failure_domain_aliases_are_present():
    raw_queue = read_python_file(Path("Virus_Scan/scheduler/execution/process_queue_runner.py"))
    jsonio = read_python_file(Path("Virus_Scan/core/jsonio.py"))
    assert "RAW_QUEUE_RECOVERABLE_EXCEPTIONS" in raw_queue
    assert "JSON_PERSISTENCE_EXCEPTIONS" in jsonio
    assert "except RAW_QUEUE_RECOVERABLE_EXCEPTIONS" in raw_queue
    assert "except JSON_PERSISTENCE_EXCEPTIONS" in jsonio
