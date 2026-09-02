from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models import markov
from Virus_Scan.models.behavior_sequence_contract import canonical_behavior_event_name
from Virus_Scan.models.markov import flow as markov_flow

MARKOV_MODEL = Path("Virus_Scan/models/markov/flow.py")


def test_stage1126_markov_uses_model_owned_sequence_admission_contract() -> None:
    source = MARKOV_MODEL.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(MARKOV_MODEL))
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    assert "_canonical_behavior_event_name" not in function_names
    assert not hasattr(markov_flow, "_behavior_sequence_contract_name")
    assert markov_flow.canonical_behavior_event_name is canonical_behavior_event_name


def test_stage1126_markov_flow_preserves_mapping_while_filtering_context_only_events() -> None:
    flow = markov.canonical_behavior_flow([
        " API_LoadURL ",
        {"tag": "api_loadurl"},
        {"behavior": "tag_process_spawn"},
        "url_present",
        "strict_fast_prefilter_hit",
        {"event": "network_download"},
        {"raw": "network_download"},
    ])

    assert flow == ("loadurl", "process_spawn", "network_download")
