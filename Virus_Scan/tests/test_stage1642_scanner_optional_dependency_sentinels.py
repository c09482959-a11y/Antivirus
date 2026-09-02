from __future__ import annotations

import ast
from pathlib import Path

import Virus_Scan.scanners.binary_resource_metrics as binary_resource_metrics
import Virus_Scan.scanners.image_lsb as image_lsb
import Virus_Scan.scheduler.runtime.execution_memory_capacity as execution_memory_capacity
import Virus_Scan.scheduler.runtime.backpressure_targets as backpressure_targets


def _assigned_none_names(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and node.value.value is None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def test_stage1642_binary_resource_metrics_psutil_is_explicit_unavailable_sentinel_not_none() -> None:
    assert "psutil" not in _assigned_none_names("Virus_Scan/scanners/binary_resource_metrics.py")
    assert binary_resource_metrics.psutil is not None
    assert hasattr(binary_resource_metrics.psutil, "cpu_percent")
    assert hasattr(binary_resource_metrics.psutil, "Process")


def test_stage1642_image_lsb_pillow_is_explicit_unavailable_sentinel_not_none() -> None:
    assert "Image" not in _assigned_none_names("Virus_Scan/scanners/image_lsb.py")
    assert image_lsb.Image is not None
    assert hasattr(image_lsb.Image, "open")


def test_stage1642_scheduler_backpressure_psutil_is_explicit_unavailable_sentinel_not_none() -> None:
    assert "psutil" not in _assigned_none_names("Virus_Scan/scheduler/runtime/execution_memory_capacity.py")
    assert "psutil" not in _assigned_none_names("Virus_Scan/scheduler/runtime/backpressure_targets.py")
    assert execution_memory_capacity.psutil is not None
    assert backpressure_targets.psutil is not None
    assert hasattr(execution_memory_capacity.psutil, "virtual_memory")
    assert hasattr(execution_memory_capacity.psutil, "Process")
    assert hasattr(backpressure_targets.psutil, "cpu_percent")
