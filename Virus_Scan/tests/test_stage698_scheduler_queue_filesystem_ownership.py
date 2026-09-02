"""Stage698 scheduler queue filesystem ownership regression tests."""

from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, python_files_under


import ast
from pathlib import Path

from Virus_Scan.scheduler.runtime import queue_filesystem


def test_stage698_scheduler_queue_filesystem_primitives_are_scheduler_owned():
    queue_dir = Path("example_queue")
    assert queue_filesystem.queue_job_dirs(queue_dir) == (
        queue_dir / "pending",
        queue_dir / "active",
        queue_dir / "done",
        queue_dir / "failed",
    )
    assert queue_filesystem.queue_claim_meta_path(queue_dir / "active" / "job.json").name == "job.json.claim"
    assert len(queue_filesystem.queue_file_identity_for_path("sample.bin")) == 32
    assert queue_filesystem.process_weight_for_path("sample.bin") >= 1.0


def test_stage698_scheduler_does_not_import_private_core_queue_filesystem_helpers():
    scheduler_root = Path("Virus_Scan/scheduler")
    forbidden_modules = {
        "Virus_Scan.core.paths",
        "Virus_Scan.core.logging",
        "Virus_Scan.reporting.output",
    }
    findings = []
    for path in python_files_under("Virus_Scan/scheduler"):
        tree = parse_python_file(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.module not in forbidden_modules:
                continue
            private_names = [alias.name for alias in node.names if alias.name.startswith("_")]
            if private_names:
                findings.append((str(path), node.module, tuple(private_names)))
    assert findings == []
