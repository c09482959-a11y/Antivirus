from __future__ import annotations

from collections import Counter, defaultdict
import ast
from pathlib import Path

import pytest

from Virus_Scan.contracts.runtime_model_state import RUNTIME_MODEL_STATE_SCHEMA_VERSION
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    load_runtime_model_baselines,
    runtime_model_mapping_snapshot,
)
from Virus_Scan.tests.support.runtime_model_state import current_runtime_model_record


def _reset() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage2754_runtime_model_current_schema_is_named_and_accepted() -> None:
    _reset()
    record = current_runtime_model_record(global_tag_baseline={"download": 3})
    result = load_runtime_model_baselines(record)
    assert RUNTIME_MODEL_STATE_SCHEMA_VERSION == 4
    assert result["loaded"] is True
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE") == {"download": 3}


@pytest.mark.parametrize("schema", [3, 5, None, "4", True])
def test_stage2754_runtime_model_stale_future_missing_malformed_schema_rejected_without_mutation(schema: object) -> None:
    _reset()
    record = current_runtime_model_record(global_tag_baseline={"download": 3})
    if schema is None:
        record.pop("schema_version")
    else:
        record["schema_version"] = schema
    result = load_runtime_model_baselines(record)
    assert result["loaded"] is False
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE") == {}


def test_stage2754_runtime_model_unknown_or_missing_fields_rejected() -> None:
    _reset()
    unknown = current_runtime_model_record()
    unknown["legacy_runtime_models"] = {}
    assert load_runtime_model_baselines(unknown)["loaded"] is False
    missing = current_runtime_model_record()
    missing.pop("cluster_state")
    assert load_runtime_model_baselines(missing)["loaded"] is False


def test_stage2754_current_schema_malformed_nested_payload_is_atomic() -> None:
    _reset()
    record = current_runtime_model_record(
        global_tag_baseline={"download": 4},
        filetype_baseline={".bin": {"exec": 2.5}},
    )
    result = load_runtime_model_baselines(record)
    assert result["loaded"] is False
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE") == {}
    assert runtime_model_mapping_snapshot("FILETYPE_BASELINE") == {}


def test_stage2754_orchestration_guards_cluster_hydration_after_runtime_envelope_rejection() -> None:
    path = Path("Virus_Scan/orchestration/model_state_loader.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "load_runtime_model_state"
    )
    runtime_assignment = next(
        node for node in function.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "load_runtime_model_baselines"
    )
    failure_guard = next(
        node for node in function.body
        if isinstance(node, ast.If) and node.lineno > runtime_assignment.lineno
    )
    cluster_assignment = next(
        node for node in function.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "load_cluster_runtime_model_record"
    )
    assert any(
        isinstance(child, ast.Return)
        and isinstance(child.value, ast.Constant)
        and child.value.value is False
        for child in failure_guard.body
    )
    assert runtime_assignment.lineno < failure_guard.lineno < cluster_assignment.lineno

