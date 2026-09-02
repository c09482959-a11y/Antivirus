from __future__ import annotations

import ast
from pathlib import Path

import pytest

import Virus_Scan.core.paths as core_paths
import Virus_Scan.runtime.model_retention as runtime_model_retention
import Virus_Scan.runtime.model_state as runtime_model_state
from Virus_Scan.runtime.runtime_flags import runtime_flag_clear, runtime_flag_get


def _imports_for(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    return imports


def test_stage1443_dirty_runtime_model_pruning_and_dirty_marker_have_single_runtime_owners() -> None:
    assert not hasattr(core_paths, "maybe_prune_bounded_runtime")
    assert not hasattr(core_paths, "mark_runtime_models_dirty")
    runtime_flag_clear("runtime_model_state_dirty")
    runtime_model_state.mark_runtime_models_dirty()
    assert runtime_flag_get("runtime_model_state_dirty") is True
    assert runtime_model_retention.maybe_prune_bounded_runtime.__module__ == "Virus_Scan.runtime.model_retention"
    runtime_model_retention.maybe_prune_bounded_runtime(force=False)


def test_stage1443_model_retention_no_longer_imports_live_runtime_state_owners() -> None:
    imports = _imports_for("Virus_Scan/models/retention.py")
    assert "Virus_Scan.runtime.model_state" not in imports
    assert "Virus_Scan.runtime.temporal_state" not in imports
    assert "Virus_Scan.runtime.cache_state" not in imports
    assert "Virus_Scan.runtime.retention_runtime_state" not in imports


def test_stage1443_runtime_model_retention_exposes_narrow_runtime_api() -> None:
    assert runtime_model_retention.__all__ == (
        "maybe_prune_bounded_runtime",
        "prune_runtime_model_state_in_memory",
    )


class _HostileRetentionLimitName(str):
    touched = 0

    def lower(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("hostile lower")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("hostile str")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("hostile repr")


def test_stage1972_runtime_model_retention_limit_name_rejects_subclass_without_hooks() -> None:
    _HostileRetentionLimitName.touched = 0

    with pytest.raises(RuntimeError, match="runtime_retention_limit_name_rejected"):
        runtime_model_retention._retention_limit(_HostileRetentionLimitName("MAX_TRANSITION_KEYS"), 1)

    assert _HostileRetentionLimitName.touched == 0
