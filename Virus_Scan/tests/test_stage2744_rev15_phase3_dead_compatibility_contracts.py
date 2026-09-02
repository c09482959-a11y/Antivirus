from pathlib import Path

from Virus_Scan.scanners.binary_behavior_semantics import EffectiveEvidenceScoreRequest
from Virus_Scan.tests.support.static_inventory import read_python_file


def test_rev15_effective_evidence_request_has_no_compatibility_engine_field() -> None:
    assert tuple(EffectiveEvidenceScoreRequest.__dataclass_fields__) == (
        "file_path", "tag", "strings_blob", "api_calls", "ordered_events",
    )
    request = EffectiveEvidenceScoreRequest("sample.exe", "process_exec")
    assert not hasattr(request, "engine")


def test_rev15_dead_or_misleading_version_constants_are_physically_removed() -> None:
    sources = {
        "model_projection": read_python_file(Path("Virus_Scan/contracts/model_projection_identity.py")),
        "attack_versioning": read_python_file(Path("Virus_Scan/detection/attack/versioning.py")),
        "yara_assimilation": read_python_file(Path("Virus_Scan/detection/evidence/yara_assimilation.py")),
        "cluster_learning": read_python_file(Path("Virus_Scan/models/clustering/learning_features.py")),
    }
    forbidden = {
        "model_projection": "MODEL_PROJECTION_LEGACY_BUNDLE_SCHEMA_VERSION",
        "attack_versioning": "ATTACK_LOCK_VERSION",
        "yara_assimilation": "REVIEWED_YARA_ASSIMILATION_VERSION",
        "cluster_learning": "CLUSTER_LEARNING_FEATURE_SCHEMA_VERSION",
    }
    for key, symbol in forbidden.items():
        assert symbol not in sources[key]
