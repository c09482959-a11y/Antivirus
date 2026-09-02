"""Stage 1216: detection behavior bucket scoring reads profile probability through the snapshot boundary."""
from __future__ import annotations
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.models.profiles.staged_store_schema import default_staged_benign_store

import ast
from collections import Counter, defaultdict
from pathlib import Path
from pprint import pformat

from Virus_Scan.detection.profiles.baseline_snapshot import behavior_bucket_probability_record
from Virus_Scan.detection.scoring.behavior.bucket_validation import behavior_bucket_validation
from Virus_Scan.tests.support.profile_learning import promote_clean_observation
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.runtime.cluster_state import (
    RuntimeClusterState,
    configure_runtime_cluster_state,
)
from Virus_Scan.runtime.config_state import (
    configure_profiles_dir,
)
from Virus_Scan.runtime.model_state import configure_runtime_model_state
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.runtime.runtime_flags import runtime_flag_clear


def _isolate_profile_state(tmp_path: Path) -> None:
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
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )
    configure_runtime_cluster_state(RuntimeClusterState())
    runtime_flag_clear("runtime_model_state_dirty")
    ensure_authoritative_engine_profiles()


def _import_modules(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
    return modules


def test_behavior_bucket_validation_no_longer_imports_profile_model_directly() -> None:
    imports = _import_modules(Path("Virus_Scan/detection/scoring/behavior/bucket_validation.py"))

    assert "Virus_Scan.models.profiles" not in imports
    assert "Virus_Scan.detection.profiles.baseline_snapshot" in imports


def test_snapshot_boundary_preserves_profile_bucket_probability(tmp_path) -> None:
    _isolate_profile_state(tmp_path)
    samples = []
    for index in range(3):
        sample = tmp_path / f"payload-{index}.dll"
        sample.write_bytes(b"MZ" + bytes((index,)) + b"\0" * 63)
        promote_clean_observation("unity", sample, ["network_activity"], strings_blob="socket")
        samples.append(sample)

    probability = behavior_bucket_probability_record("unity", samples[-1], "network")
    result = behavior_bucket_validation("unity", samples[-1], physical_tag_evidence(("network_activity",)), strings_blob="socket")
    record = next(record for record in result["records"] if record["tag"] == "network_activity")

    assert probability["ready"] is True, pformat(dict(probability), width=200)
    assert probability["probability"] > 0.0
    assert probability["estimator"] == "laplace_beta_binomial_v1"
    assert record["bucket_probability"] == probability["probability"]
