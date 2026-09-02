from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.models import profiles
from Virus_Scan.models.profiles.extension_state_learning import (
    learn_extension_chains,
    update_extension_risk_baseline,
    update_extension_timeline_baseline,
)
from Virus_Scan.models.profiles.chain_records import (
    profile_chain_frequency_key,
    profile_scoreable_chain_decisions,
)



def test_profile_extension_model_learning_helpers_are_profile_owned_and_callable():
    baseline = profiles.default_extension_baseline(".py")

    tag_evidence = physical_tag_evidence((
        "bitsadmin_exec",
        "background_transfer",
        "network_download",
    ))
    chain_evidence = evaluate_chain_evidence(tags=tag_evidence)
    chains = learn_extension_chains(baseline, chain_evidence)
    risk = update_extension_risk_baseline(baseline, 42.0)
    timeline = update_extension_timeline_baseline(
        baseline,
        ["read_file", "powershell_exec", "network_download"],
    )
    vector = profiles.behavior_vector_from_scan(
        "other",
        "sample.py",
        physical_tag_evidence(("powershell_exec", "network_download")),
        ordered_events=["read_file", "powershell_exec"],
    )

    decisions = profile_scoreable_chain_decisions(chain_evidence)
    assert decisions
    assert "normal" not in chains
    assert chains["schema_version"] == 2
    assert chains["registry_version"] == chain_evidence.registry_version
    assert chains["registry_digest"] == chain_evidence.registry_digest
    assert chains["suspicious_audit"][profile_chain_frequency_key(decisions[0])] == 1
    assert risk["samples"] == 1
    assert risk["max_seen"] == 42.0
    assert timeline["sample_count"] == 1
    assert timeline["transition_counts"]["read_file->powershell_exec"] == 1
    assert len(vector) == len(profiles.VECTOR_FEATURE_NAMES)


def test_profile_public_facade_does_not_publish_internal_extension_mutators():
    for name in (
        "learn_extension_chains",
        "update_extension_risk_baseline",
        "update_extension_timeline_baseline",
    ):
        assert name not in profiles.__all__
        assert not hasattr(profiles, name)


def test_adaptive_model_score_uses_profile_owner_not_routing_extension_model_path():
    model_score_source = read_python_file(Path("Virus_Scan/detection/scoring/adaptive/model_score.py"))
    evidence_projection_source = read_python_file(Path("Virus_Scan/detection/scoring/adaptive/evidence_projection.py"))
    feature_bundle_source = read_python_file(Path("Virus_Scan/detection/scoring/adaptive/feature_bundle.py"))
    model_score_tree = ast.parse(model_score_source)
    evidence_projection_tree = ast.parse(evidence_projection_source)
    feature_bundle_tree = ast.parse(feature_bundle_source)
    model_score_imports = {
        node.module
        for node in ast.walk(model_score_tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    evidence_projection_imports = {
        node.module
        for node in ast.walk(evidence_projection_tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    feature_bundle_imports = {
        node.module
        for node in ast.walk(feature_bundle_tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }

    assert "Virus_Scan.detection.scoring.adaptive.evidence_projection" in model_score_imports
    assert "Virus_Scan.detection.scoring.adaptive.feature_bundle" in evidence_projection_imports
    assert "Virus_Scan.models.profiles" not in feature_bundle_imports
    assert "Virus_Scan.models.api.adaptive_signals" in feature_bundle_imports
    assert "Virus_Scan.routing.extensions" not in model_score_imports
    assert "Virus_Scan.routing.extensions" not in feature_bundle_imports


def test_routing_extensions_no_longer_owns_profile_model_learning_functions():
    source = read_python_file(Path("Virus_Scan/routing/extensions.py"))
    tree = ast.parse(source)
    function_names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }

    assert "extension_profile_anomaly" not in function_names
    assert "coordinated_model_validation_signal" not in function_names
    assert "update_extension_timeline_baseline" not in function_names
    assert "learn_extension_chains" not in function_names
