from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.workers.inmemory_dispatch_backpressure import decide_inmemory_dispatch_backpressure


ROOT = Path(__file__).resolve().parents[2]


def test_stage2027_inmemory_backpressure_uses_no_hook_integer_materializer() -> None:
    pause, reason = decide_inmemory_dispatch_backpressure(
        active_heavy_weight=0,
        logical_slots=object(),
        workers=object(),
        pressure_snapshot={"pressure": "high"},
    )

    assert pause is False
    assert reason == ""


def test_stage2027_scheduler_static_undefined_names_removed_from_target_sources() -> None:
    targets = {
        "Virus_Scan/scheduler/internal/immutable_output_support.py": "materialize_scheduler_mapping",
        "Virus_Scan/scheduler/workers/inmemory_dispatch_backpressure.py": "no_hook_exact_nonnegative_int",
    }
    for relative, name in targets.items():
        module = ast.parse((ROOT / relative).read_text(encoding="utf-8"), filename=relative)
        loaded_names = {node.id for node in ast.walk(module) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
        imported_names = {
            alias.asname or alias.name
            for node in ast.walk(module)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_names.update(
            alias.asname or alias.name
            for node in ast.walk(module)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        )
        defined_names = {node.name for node in ast.walk(module) if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        if name in loaded_names:
            assert name in imported_names or name in defined_names
