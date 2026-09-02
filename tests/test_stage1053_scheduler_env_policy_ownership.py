from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot
from Virus_Scan.scheduler.runtime.resource_priority import apply_resource_priority_profile, resource_priority_snapshot
from Virus_Scan.publication.api import write_partial_scan_results


def test_stage1053_scheduler_process_environment_access_is_centralized() -> None:
    allowed = {Path("Virus_Scan/scheduler/runtime/env_policy.py")}
    offenders: list[str] = []
    for path in Path("Virus_Scan/scheduler").rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr in {"environ", "getenv"}
                and isinstance(node.value, ast.Name)
                and node.value.id == "os"
                and path not in allowed
            ):
                offenders.append(f"{path}:{node.lineno}: os.{node.attr}")
    assert offenders == []


def test_stage1053_scheduler_environment_snapshot_is_immutable_and_detached() -> None:
    source = {"UMIGE_PROCESS_QUEUE_MAX_CHILDREN": "5", "UMIGE_DYNAMIC_QUEUE_FEED": "1"}
    snapshot = scheduler_environment_snapshot(source)
    source["UMIGE_PROCESS_QUEUE_MAX_CHILDREN"] = "99"
    assert snapshot["UMIGE_PROCESS_QUEUE_MAX_CHILDREN"] == "5"
    try:
        snapshot["UMIGE_PROCESS_QUEUE_MAX_CHILDREN"] = "7"  # type: ignore[index]
    except TypeError:
        pass
    else:  # pragma: no cover - defensive assertion for immutable mapping contract
        raise AssertionError("scheduler environment snapshot accepted mutation")


def test_stage1053_resource_priority_uses_explicit_scheduler_environment_target() -> None:
    target_env: dict[str, str] = {}
    profile, cfg = apply_resource_priority_profile("low", env=target_env)
    snapshot = resource_priority_snapshot(env=target_env)
    assert profile == "low"
    assert target_env["UMIGE_RESOURCE_PRIORITY"] == "low"
    assert target_env["UMIGE_PROCESS_QUEUE_MAX_CHILDREN"] == str(cfg["process_queue_max_children"])
    assert snapshot["profile"] == "low"
    assert snapshot["config"]["process_queue_max_children"] == cfg["process_queue_max_children"]


def test_stage1053_scheduler_uses_public_publication_api_only() -> None:
    offenders: list[str] = []
    for path in Path("Virus_Scan/scheduler").rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.ImportFrom):
                modules.append(node.module or "")
            elif isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            for module in modules:
                if module.startswith("Virus_Scan.publication") and not module.startswith("Virus_Scan.publication.api"):
                    offenders.append(f"{path}:{node.lineno}: {module}")
    assert offenders == []


def test_stage1053_publication_api_exports_partial_writer() -> None:
    assert callable(write_partial_scan_results)
