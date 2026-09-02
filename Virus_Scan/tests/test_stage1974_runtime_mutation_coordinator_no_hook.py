import ast
from pathlib import Path

import pytest

from Virus_Scan.runtime.mutation_coordinator import RuntimeRoot


def test_stage1974_mutation_coordinator_messages_preserve_exact_runtime_behavior() -> None:
    root = RuntimeRoot()
    assert root.mutate(
        "runtime",
        "root.stage1974",
        {"ok": True},
        kind="event",
        lineage_id="stage1974-mutation",
    ) == {"ok": True}

    volatility = dict(root.domain("runtime").volatility())
    assert volatility["hot_keys"]["root.stage1974"] == 1

    root.domain("runtime").freeze()
    with pytest.raises(RuntimeError) as frozen_error:
        root.mutate("runtime", "root.blocked", "value", kind="event")
    assert str(frozen_error.value) == "runtime domain runtime is frozen"


def test_stage1974_mutation_coordinator_rejection_messages_use_exact_text() -> None:
    root = RuntimeRoot()

    with pytest.raises(RuntimeError) as undeclared_error:
        root.domain("stage1974_shadow")
    assert str(undeclared_error.value) == (
        "undeclared runtime mutation domain: stage1974_shadow"
    )

    scheduler = root.domain("scheduler")
    with pytest.raises(RuntimeError) as ownership_error:
        scheduler.set("root.stage1974_cross_domain", "leak", kind="event")
    assert str(ownership_error.value) == "runtime domain scheduler does not own key"


def test_stage1974_mutation_coordinator_static_no_hook_routes_do_not_regress() -> None:
    source_path = Path("Virus_Scan/runtime/mutation_coordinator.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))

    joined_strings = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]
    unsafe_items_calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "items":
            continue
        if isinstance(func.value, ast.Name) and func.value.id == "dict":
            continue
        unsafe_items_calls.append(node.lineno)

    assert joined_strings == []
    assert unsafe_items_calls == []
