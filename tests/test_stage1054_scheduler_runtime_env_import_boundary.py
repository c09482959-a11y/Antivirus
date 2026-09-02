
"""Stage 1054 Phase 5 regression tests for scheduler runtime env ownership."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scheduler.runtime.raw_worker_capacity import raw_worker_pool_cap, stage_parallel_workers


def _imports_from(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
    return modules


def test_stage1054_resource_priority_does_not_read_env_at_import() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/runtime/resource_priority.py"))
    assert "contracts.env_config" not in source
    assert "str_env(" not in source
    assert "RESOURCE_PRIORITY_PROFILE = \"high\"" in source


def test_stage1054_raw_worker_capacity_does_not_bind_runtime_env_constant() -> None:
    path = Path("Virus_Scan/scheduler/runtime/raw_worker_capacity.py")
    source = path.read_text(encoding="utf-8")
    modules = _imports_from(path)
    assert "Virus_Scan.runtime.constants" not in modules
    assert "from Virus_Scan.runtime.constants import STAGE_PARALLEL_DEFAULT_WORKERS" not in source
    assert "default=STAGE_PARALLEL_DEFAULT_WORKERS" not in source
    assert "SCHEDULER_STAGE_PARALLEL_DEFAULT_WORKERS = 6" in source


def test_stage1054_worker_capacity_preserves_injected_env_values() -> None:
    env = {"UMIGE_STAGE_PARALLEL_WORKERS": "9", "UMIGE_RAW_WORKER_POOL_CAP": "13"}
    assert stage_parallel_workers(env=env) == 9
    assert raw_worker_pool_cap(env=env) == 13
