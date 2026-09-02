"""Stage 960 repository test-audit coverage for scheduler queue runtime API contracts.

The Stage 959 package dropped ``Virus_Scan.scheduler.queue`` while production
still imported it through ``Virus_Scan.scheduler.api.runtime``.  These tests lock
that package as the canonical queue owner rather than allowing the public runtime
API to drift into missing imports, fallback shims, or private runtime paths.
"""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.api import runtime as scheduler_runtime_api
from Virus_Scan.scheduler import queue as scheduler_queue_package
from Virus_Scan.scheduler.queue import admission as queue_admission_module
from Virus_Scan.scheduler.queue import identity_index as queue_identity_index_module
from Virus_Scan.scheduler.queue import raw_retry_job as queue_raw_retry_job_module


def test_stage960_scheduler_queue_package_is_present_and_runtime_api_uses_canonical_queue_owners() -> None:
    assert Path(scheduler_queue_package.__file__).name == "__init__.py"
    assert Path(queue_raw_retry_job_module.__file__).name == "raw_retry_job.py"
    assert Path(queue_identity_index_module.__file__).name == "identity_index.py"
    assert Path(queue_admission_module.__file__).name == "admission.py"

    assert scheduler_runtime_api.prepare_raw_retry_job.__module__ == "Virus_Scan.scheduler.queue.raw_retry_job"
    assert scheduler_runtime_api.note_identity_for_queue.__module__ == "Virus_Scan.scheduler.queue.identity_index"
    assert scheduler_runtime_api.workload_plan_summary.__module__ == "Virus_Scan.scheduler.queue.admission"


def test_stage960_public_runtime_prepare_raw_retry_job_preserves_retry_generation_and_evidence() -> None:
    retry = scheduler_runtime_api.prepare_raw_retry_job(
        {"path": "sample.rpa", "attempt": 0, "max_retries": 2, "worker_pid": 4411},
        {"error": "temporary raw decode failure"},
        now=42.0,
    )

    assert retry is not None
    assert retry["attempt"] == 1
    assert retry["generation"] == 1
    assert retry["raw_retry_from_attempt"] == 0
    assert retry["retried"] is True
    assert retry["last_error"] == "temporary raw decode failure"
    assert retry["retry_pending_active"] is True
    assert retry["retry_pending_generation"] == 1
    assert retry["retry_pending_reason"] == "temporary raw decode failure"
    assert retry["job_type"] == "raw_stage"
    assert retry["history"][-1]["pid"] == 4411

    assert scheduler_runtime_api.prepare_raw_retry_job(retry, {"error": "duplicate"}, now=43.0) is None
    assert scheduler_runtime_api.prepare_raw_retry_job({"attempt": 2, "max_retries": 2}, {"error": "done"}) is None


def test_stage960_public_runtime_workload_summary_classifies_queue_work_by_verified_extensions() -> None:
    summary = scheduler_runtime_api.workload_plan_summary(
        scheduler_runtime_api.build_workload_classification_plan([
            "archives/game.rpa",
            "managed/Assembly-CSharp.dll",
            "rules/custom.yara",
            "media/title.png",
            "scripts/bootstrap.rpy",
            "unknown/readme.bin",
        ])
    )

    counts = summary["counts"]
    assert summary["separated"] == 1
    assert counts["archive"] == 1
    assert counts["dotnet"] == 1
    # The canonical classification plan has no stage/tag evidence here; YARA is
    # stage/tag-driven in production, so a .yara path remains generic here.
    assert counts["yara"] == 0
    assert counts["image"] == 1
    assert counts["script"] == 1
    assert counts["generic"] == 2
    assert "limits" in summary
    assert "cost" in summary


def test_stage960_scheduler_runtime_api_static_import_boundary_has_no_dynamic_or_function_imports() -> None:
    source = Path(scheduler_runtime_api.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    forbidden_dynamic_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "__import__"
    ]
    function_scope_imports = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        and any(isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)) for parent in ast.walk(tree) if node in ast.iter_child_nodes(parent))
    ]

    assert forbidden_dynamic_calls == []
    assert function_scope_imports == []
    assert "Virus_Scan.scheduler.queue.raw_retry_job" in source
    assert "Virus_Scan.scheduler.queue.identity_index" in source
    assert "Virus_Scan.scheduler.queue.admission" in source
