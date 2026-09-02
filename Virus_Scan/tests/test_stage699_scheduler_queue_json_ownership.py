from Virus_Scan.tests.support.static_inventory import parse_python_file, python_files_under

import ast
import json
from pathlib import Path


from Virus_Scan.scheduler.runtime.queue_json import (
    _queue_write_json_replace,
    read_json_file,
    make_json_safe,
)


def _imports_from(path: Path):
    tree = parse_python_file(path)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            yield node.module or "", {alias.name for alias in node.names}


def test_scheduler_queue_domains_do_not_import_private_core_jsonio_helpers():
    root = Path("Virus_Scan/scheduler")
    offenders = []
    for path in python_files_under("Virus_Scan/scheduler"):
        for module, names in _imports_from(path):
            if module == "Virus_Scan.core.jsonio":
                private_names = sorted(name for name in names if name.startswith("_"))
                if private_names:
                    offenders.append((str(path), tuple(private_names)))
    assert offenders == []


def test_scheduler_owned_queue_json_round_trip_validates_semantics(tmp_path):
    target = tmp_path / "job.json"
    payload = {
        "job_type": "file",
        "file": "sample.bin",
        "queue_identity": "identity-1",
        "result": {"file": "sample.bin", "classification": "clean", "score": 0.0},
    }
    assert _queue_write_json_replace(target, payload, verify=True, log_context="stage699_round_trip")
    loaded = read_json_file(target, default=None)
    assert loaded["job_type"] == "file"
    assert loaded["queue_identity"] == "identity-1"
    assert loaded["schema_version"] >= 1


def test_scheduler_owned_json_safe_truncates_bulky_values():
    value = make_json_safe({"decoded_text": "x" * 3000})
    assert value["decoded_text"]["truncated"] is True
    assert value["decoded_text"]["chars"] == 3000
