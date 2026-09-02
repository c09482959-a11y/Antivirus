from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path
from unittest.mock import patch

from Virus_Scan.models.profiles import coordinated_validation
from Virus_Scan.models.profiles.snapshots import default_extension_baseline


class HostileSubmodelMapping(dict):
    touched = 0

    def get(self, key, default=None):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("coordinated validation must not call caller-owned mapping get")


def _patch_submodels(*, bucket, vector, temporal, markov, timeline):
    return (
        patch.object(
            coordinated_validation,
            "get_extension_baseline",
            return_value=default_extension_baseline(".rpy"),
        ),
        patch.object(coordinated_validation, "profile_behavior_bucket_validation", return_value=bucket),
        patch.object(coordinated_validation, "behavior_vector_from_scan", return_value=[0.1]),
        patch.object(coordinated_validation, "vector_baseline_anomaly", return_value=vector),
        patch.object(coordinated_validation, "snapshot_temporal", return_value=temporal),
        patch.object(coordinated_validation, "compute_markov_features", return_value=markov),
        patch.object(coordinated_validation, "extension_timeline_anomaly", return_value=timeline),
    )


def test_stage2023_coordinated_validation_preserves_exact_primitive_boosts() -> None:
    patches = _patch_submodels(
        bucket={"bucket_anomaly": 1.0, "filetype_validation": {"filetype_anomaly": 1.0}},
        vector={"anomaly": 1.0},
        temporal={"ready": True, "belief": 1.0},
        markov={"ready": True, "transition": 1.0, "rarity": 0.5, "pair_anomaly": 0.25},
        timeline={"anomaly": 1.0},
    )

    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
        result = coordinated_validation.coordinated_model_validation_signal("renpy", "game.rpy", ("renpy_script",))

    assert result["ready"] is True
    assert result["model_anomaly"] == 1.0
    assert result["temporal_support"] == 1.0
    assert result["markov_support"] == 1.0
    assert result["timeline_support"] == 1.0
    assert result["filetype_validation"] == {"filetype_anomaly": 1.0}


def test_stage2023_coordinated_validation_rejects_hostile_submodel_mapping_hooks() -> None:
    HostileSubmodelMapping.touched = 0
    hostile = HostileSubmodelMapping(
        {
            "ready": True,
            "belief": 1.0,
            "transition": 1.0,
            "bucket_anomaly": 1.0,
            "filetype_validation": {"filetype_anomaly": 1.0},
            "anomaly": 1.0,
        }
    )
    patches = _patch_submodels(bucket=hostile, vector=hostile, temporal=hostile, markov=hostile, timeline=hostile)

    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
        result = coordinated_validation.coordinated_model_validation_signal("renpy", "game.rpy", ("renpy_script",))

    assert result["model_anomaly"] == 0.0
    assert result["temporal_support"] == 0.0
    assert result["markov_support"] == 0.0
    assert result["timeline_support"] == 0.0
    assert HostileSubmodelMapping.touched == 0


def test_stage2023_coordinated_validation_source_uses_no_hook_metric_readers() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/coordinated_validation.py"))

    assert "safe_clamp" not in source
    assert "temporal_snapshot.get(" not in source
    assert "mf.get(" not in source
    assert "timeline_v.get(" not in source
    assert "bucket_v.get(" not in source
    assert "vector_v.get(" not in source
