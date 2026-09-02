from __future__ import annotations

from Virus_Scan.models import temporal


def test_stage1453_temporal_root_does_not_reexport_markov_public_api():
    assert "canonical_behavior_flow" not in temporal.__all__
    assert "compute_markov_features" not in temporal.__all__
    assert not hasattr(temporal, "canonical_behavior_flow")
    assert not hasattr(temporal, "compute_markov_features")
