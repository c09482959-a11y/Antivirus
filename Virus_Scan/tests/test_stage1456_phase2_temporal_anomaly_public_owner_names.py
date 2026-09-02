from Virus_Scan.tests.support.static_inventory import parse_python_file, read_python_file

import ast
from pathlib import Path

import Virus_Scan.models.temporal.accumulator as temporal_accumulator
import Virus_Scan.models.temporal.anomaly as temporal_anomaly
import Virus_Scan.models.temporal.overlay as temporal_overlay
import Virus_Scan.models.temporal.policy as temporal_policy


def test_stage1456_temporal_anomaly_exports_only_markov_and_event_owners():
    assert set(temporal_anomaly.__all__) == {
        "temporal_flat_events", "temporal_pair_anomaly",
        "temporal_stage_sequence_anomaly",
    }
    assert not any(name.startswith("_") for name in temporal_anomaly.__all__)
    assert not hasattr(temporal_anomaly, "temporal_phase_progression_score")
    assert not hasattr(temporal_anomaly, "temporal_high_risk_burst_score")


def test_stage1456_phase_and_burst_policy_have_one_canonical_owner():
    assert {
        "temporal_phase_progression_evidence",
        "temporal_burst_policy_evidence",
        "temporal_delay_policy_evidence",
    }.issubset(set(temporal_policy.__all__))
    source = read_python_file(Path("Virus_Scan/models/temporal/validation.py"))
    tree = ast.parse(source)
    policy_imports = {
        alias.name for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module == "Virus_Scan.models.temporal.policy"
        for alias in node.names
    }
    assert policy_imports == {
        "TEMPORAL_POLICY_VERSION", "temporal_burst_policy_evidence",
        "temporal_delay_policy_evidence", "temporal_phase_progression_evidence",
    }


def test_stage1456_chain_policy_is_imported_by_validation_support_owner():
    tree = parse_python_file(Path("Virus_Scan/models/temporal/validation_support.py"))
    imports = {
        alias.name for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module == "Virus_Scan.detection.api.chain_evaluation"
        for alias in node.names
    }
    assert imports == {"evaluate_chain_evidence"}


def test_stage1456_overlay_and_accumulator_use_current_public_owners():
    assert set(temporal_overlay.__all__) == {
        "temporal_markov_overlay_support", "transition_probability_overlay",
    }
    assert set(temporal_accumulator.__all__) == {
        "TEMPORAL_ACCUMULATOR_DECAY_VERSION",
        "TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC",
        "TEMPORAL_ACCUMULATOR_MIN_SUPPORT",
        "TEMPORAL_ACCUMULATOR_VERSION",
        "TemporalAccumulatorState",
        "initial_temporal_accumulator_state",
        "temporal_evidence_accumulator_update",
    }
    assert not Path("Virus_Scan/models/temporal/decay.py").exists()


def test_stage1456_temporal_validation_imports_no_private_temporal_helpers():
    tree = parse_python_file(Path("Virus_Scan/models/temporal/validation.py"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("Virus_Scan.models.temporal"):
            assert not any(alias.name.startswith("_") for alias in node.names)
