from pathlib import Path

from Virus_Scan import chains, tags
from Virus_Scan.detection.chains.execution import anchors as detection_chains
from Virus_Scan.detection.tags import evidence_generation as detection_tag_generation
from Virus_Scan.models import clustering as model_clustering
from Virus_Scan.models import markov as model_markov
from Virus_Scan.models import temporal as model_temporal


def test_full_tree_short_non_model_subsystem_import_contract():
    modules = [tags, chains]
    for module in modules:
        assert getattr(module, "__all__")


def test_stage1166_root_model_compatibility_modules_are_not_public_paths():
    root = Path("Virus_Scan")
    assert not (root / "Markov.py").exists()
    assert not (root / "temporal.py").exists()
    assert not (root / "clustering.py").exists()


def test_short_subsystem_entrypoints_publish_canonical_objects():
    assert tags.finalize_tag_evidence_generation is detection_tag_generation.finalize_tag_evidence_generation
    assert chains.evaluate_chain_evidence is detection_chains.evaluate_chain_evidence
    assert model_temporal.snapshot_temporal is model_temporal.snapshot_temporal
    assert model_markov.compute_markov_features is model_markov.compute_markov_features
    assert model_clustering.build_feature_vector is model_clustering.build_feature_vector
