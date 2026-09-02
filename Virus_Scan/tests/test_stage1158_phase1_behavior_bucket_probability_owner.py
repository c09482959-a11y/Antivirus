"""Stage 1158: behavior bucket probability is model-profile owned, not a detection/scanner stub."""
from __future__ import annotations
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.models.profiles.staged_store_schema import default_staged_benign_store

import ast
from pathlib import Path

from Virus_Scan.detection.scoring.behavior.bucket_validation import behavior_bucket_validation
from Virus_Scan.tests.support.profile_learning import promote_clean_observation
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.runtime.config_state import (
    configure_profiles_dir,
)
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state


def _isolate_profile_state(tmp_path: Path) -> None:
    configure_runtime_cluster_state(RuntimeClusterState())
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    configure_profiles_dir(str(profiles_dir))
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles_dir))
    state.clear_all_profiles()
    state.set_staged_cache(
        default_staged_benign_store(),
        dirty=False,
    )
    ensure_authoritative_engine_profiles()


def test_behavior_bucket_validation_uses_profile_probability_owner(tmp_path):
    _isolate_profile_state(tmp_path)
    samples = []
    for index in range(3):
        sample = tmp_path / f"payload-{index}.dll"
        sample.write_bytes(b"MZ" + bytes((index,)) + b"\0" * 63)
        promote_clean_observation("unity", sample, ["network_activity"], strings_blob="socket")
        samples.append(sample)
    result = behavior_bucket_validation("unity", samples[-1], physical_tag_evidence(("network_activity",)), strings_blob="socket")
    record = next(record for record in result["records"] if record["tag"] == "network_activity")
    assert record["bucket"] == "network"
    assert record["bucket_probability"] > 0.0


def test_detection_bucket_validation_has_no_fake_zero_probability_stub():
    path = Path("Virus_Scan/detection/scoring/behavior/bucket_validation.py")
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assert "_bucket_probability" not in function_names
    assert "behavior_bucket_probability" in source


def test_scanner_duplicate_behavior_bucket_probability_owner_removed():
    assert not Path("Virus_Scan/scanners/binary_behavior_profiles.py").exists()
