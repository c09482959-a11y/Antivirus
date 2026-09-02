from __future__ import annotations

import inspect

from Virus_Scan.orchestration.model_state_loader import load_runtime_model_state


def test_stage1668_orchestration_loader_has_no_external_path_contract() -> None:
    assert tuple(inspect.signature(load_runtime_model_state).parameters) == ()
