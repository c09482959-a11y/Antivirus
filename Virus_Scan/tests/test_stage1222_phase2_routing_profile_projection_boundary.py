from pathlib import Path

from Virus_Scan.routing.profile_model_projection import default_routing_engine_profile


ROOT = Path(__file__).resolve().parents[1]


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_routing_decision_files_do_not_import_profile_model_directly():
    engine_detect_source = _source("routing/engine_detect.py")
    lifecycle_source = _source("orchestration/lifecycle.py")

    assert "from Virus_Scan.models.profiles" not in engine_detect_source
    assert "import Virus_Scan.models.profiles" not in engine_detect_source
    assert "from Virus_Scan.models.profiles" not in lifecycle_source
    assert "import Virus_Scan.models.profiles" not in lifecycle_source

    assert "from Virus_Scan.routing.profile_model_projection import" in engine_detect_source
    assert "from Virus_Scan.routing.profile_model_projection import ProfileSchemaInvariantError" in lifecycle_source


def test_profile_projection_preserves_default_profile_shape():
    profile = default_routing_engine_profile("renpy")

    assert profile["engine"] == "renpy"
    assert "schema_version" in profile
    assert isinstance(profile.get("extension_baselines"), dict)
