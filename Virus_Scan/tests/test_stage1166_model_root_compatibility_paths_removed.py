from pathlib import Path
from Virus_Scan.models import clustering, markov, temporal


def test_stage1166_model_root_compatibility_paths_removed():
    root = Path("Virus_Scan")
    assert not (root / "Markov.py").exists()
    assert not (root / "temporal.py").exists()
    assert not (root / "clustering.py").exists()


def test_stage1166_model_callers_use_canonical_model_modules():
    assert callable(markov.compute_markov_features)
    assert callable(temporal.snapshot_temporal)
    assert callable(clustering.build_feature_vector)
