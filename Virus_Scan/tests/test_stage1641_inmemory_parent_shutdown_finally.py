from __future__ import annotations

import ast
from pathlib import Path


def test_stage1641_inmemory_parent_loop_shutdown_is_inside_finally() -> None:
    path = Path("Virus_Scan/scheduler/orchestration/inmemory_parent_loop.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    run_function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_run_longlived_process_queue"
    )
    try_nodes = [node for node in ast.walk(run_function) if isinstance(node, ast.Try)]
    shutdown_in_finally = False
    shutdown_after_try_body = False
    for try_node in try_nodes:
        for final_node in try_node.finalbody:
            if any(
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "shutdown_inmemory_parent_runtime"
                for call in ast.walk(final_node)
            ):
                shutdown_in_finally = True
        for body_node in try_node.body:
            if any(
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "shutdown_inmemory_parent_runtime"
                for call in ast.walk(body_node)
            ):
                shutdown_after_try_body = True

    assert shutdown_in_finally is True
    assert shutdown_after_try_body is False
