from __future__ import annotations
from Virus_Scan.tests.support.runtime_model_state import current_runtime_model_record

import ast
from collections import Counter, defaultdict
from pathlib import Path

from Virus_Scan.contracts.markov_learning import (
    markov_context_support_key,
    markov_event_transition_key,
    markov_event_vocabulary_key,
    markov_global_context_key,
    markov_stage_transition_key,
    markov_stage_vocabulary_key,
)
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    load_runtime_model_baselines,
    runtime_model_mapping_snapshot,
    runtime_transition_counter_snapshot,
    runtime_transition_key_from_json,
    runtime_transition_key_to_json,
)

MARKOV_MODEL = Path("Virus_Scan/models/markov.py")


def _reset_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage1165_runtime_model_baseline_loader_executes_immediately_and_restores_markov_counts() -> None:
    _reset_state()
    context = markov_global_context_key()
    event_key = markov_event_transition_key(
        context_key=context, previous_stage="asset", source_event="download",
    )
    stage_key = markov_stage_transition_key(
        context_key=context, previous_stage="asset", behavior_flow=("download", "exec"),
    )
    payload = {
        "transition_counts": [
            {**runtime_transition_key_to_json(event_key), "target": "exec", "count": 4},
            {**runtime_transition_key_to_json(stage_key), "target": "runtime", "count": 4},
            {**runtime_transition_key_to_json(markov_context_support_key(context)), "target": "observations", "count": 4},
            {**runtime_transition_key_to_json(markov_event_vocabulary_key(context)), "target": "download", "count": 4},
            {**runtime_transition_key_to_json(markov_event_vocabulary_key(context)), "target": "exec", "count": 4},
            {**runtime_transition_key_to_json(markov_stage_vocabulary_key(context)), "target": "runtime", "count": 4},
        ],
        "global_tag_baseline": {"download": 4, "exec": 4},
        "global_tag_pair_baseline": [{"a": "download", "b": "exec", "count": 4}],
        "filetype_baseline": {".rpy": {"download": 2, "exec": 2}},
    }

    result = load_runtime_model_baselines(current_runtime_model_record(payload))

    assert result["loaded"] is True
    assert result["reason"] is None
    assert result["records_loaded"] >= 9
    assert result["model_state_unavailable_reasons"] == ()
    assert runtime_transition_counter_snapshot(stage_key)["runtime"] == 4
    assert runtime_transition_counter_snapshot(event_key)["exec"] == 4
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE")["download"] == 4
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_PAIR_BASELINE")[("download", "exec")] == 4
    assert runtime_model_mapping_snapshot("FILETYPE_BASELINE")[".rpy"]["exec"] == 2


def test_stage1165_runtime_owns_transition_json_materialization_and_markov_has_no_dead_duplicate_helpers() -> None:
    key = runtime_transition_key_from_json({
        "type": "markov_event_v2",
        "context": "global:trusted_benign",
        "previous_stage": "asset",
        "source_event": "decode",
    })
    assert key == (
        "markov_event_v2",
        ("global:trusted_benign", "asset", "decode"),
    )

    functions = set()
    for path in Path("Virus_Scan/models/markov").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        functions.update(node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef))

    assert "_runtime_transition_key_from_json" not in functions
    assert "_runtime_transition_key_to_json" not in functions
