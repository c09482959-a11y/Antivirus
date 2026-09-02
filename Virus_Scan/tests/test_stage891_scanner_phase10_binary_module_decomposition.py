from Virus_Scan.scanners import binary
from Virus_Scan.scanners import binary_behavior_detectors
from Virus_Scan.scanners import binary_failover
from Virus_Scan.scanners import binary_filetype
from Virus_Scan.scanners import binary_resources

import ast
from pathlib import Path


def _module(name: str) -> Path:
    return Path("Virus_Scan/scanners") / name


def test_binary_public_surface_contains_no_duplicate_scanner_logic():
    source = _module("binary.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    functions = [node.name for node in tree.body if isinstance(node, ast.FunctionDef)]
    assert functions == []
    assert "from Virus_Scan.scanners.binary_behavior import" in source
    assert "from Virus_Scan.scanners.binary_resources import" not in source
    assert "from Virus_Scan.scanners.binary_filetype import" in source
    assert "from Virus_Scan.scanners.binary_failover import" in source


def test_binary_phase10_bounded_modules_stay_under_size_gate():
    checked = [
        "binary.py",
        "binary_behavior.py",
        "binary_behavior_detectors.py",
        "binary_behavior_predicates.py",
        "binary_bits.py",
        "binary_failover.py",
        "binary_filetype.py",
        "binary_raw_escalation.py",
        "binary_resource_metrics.py",
        "binary_resources.py",
        "binary_runtime_evidence.py",
        "binary_stage_tasks.py",
        "binary_strict_fast.py",
    ]
    oversized = []
    for name in checked:
        line_count = len(_module(name).read_text(encoding="utf-8").splitlines())
        if line_count > 200:
            oversized.append((name, line_count))
    assert oversized == []


def test_binary_phase10_no_imports_inside_functions():
    offenders = []
    for path in sorted(Path("Virus_Scan/scanners").glob("binary*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]:
            for child in ast.walk(function):
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    offenders.append((path.as_posix(), function.name, child.lineno))
    assert offenders == []


def test_binary_public_exports_delegate_to_canonical_modules():

    assert binary.should_binary_failover is binary_failover.should_binary_failover
    assert binary.filetype_validation_context is binary_filetype.filetype_validation_context
    assert binary.detect_attack_chain is binary_behavior_detectors.detect_attack_chain
    assert callable(binary_resources._umige_raw_should_escalate_after_triage_inmemory)
    assert not hasattr(binary, "_umige_raw_should_escalate_after_triage_inmemory")
