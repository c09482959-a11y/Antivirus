from Virus_Scan.engine import EngineIdentity, engine_identity_from_record, normalize_engine_name


def test_engine_namespace_imports_without_runtime_hydration():
    assert normalize_engine_name("Unity") == "unity"
    assert normalize_engine_name("unknown-engine") == "other"


def test_engine_identity_snapshot_is_immutable_and_normalized():
    identity = engine_identity_from_record({
        "container_engine": "RenPy",
        "artifact_engine": "Unity",
        "detected_engine": "RPGM",
    })
    assert identity == EngineIdentity("renpy", "unity", "rpgm")
