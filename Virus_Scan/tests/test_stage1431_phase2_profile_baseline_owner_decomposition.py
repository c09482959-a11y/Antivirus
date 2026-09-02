from pathlib import Path

from Virus_Scan.tests.support.static_inventory import read_python_file
from Virus_Scan.models import profiles
from Virus_Scan.models.profiles import baseline as profile_baseline
from Virus_Scan.models.profiles import vector_anomaly as profile_vector_anomaly
from Virus_Scan.models.profiles.vector_statistics import default_profile_vector_statistics


from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
def test_stage1431_profile_baseline_owners_are_explicit_package_modules():
    assert Path("Virus_Scan/models/profiles/baseline.py").exists()
    assert Path("Virus_Scan/models/profiles/vector_anomaly.py").exists()
    assert profiles.profile_behavior_bucket_validation.__module__ == "Virus_Scan.models.profiles.baseline"
    assert profiles.apply_library_behavior_baseline.__module__ == "Virus_Scan.models.profiles.baseline"
    assert profiles.vector_baseline_anomaly.__module__ == "Virus_Scan.models.profiles.vector_anomaly"


def test_stage1431_profile_api_imports_canonical_owners_without_cycle_or_late_import():
    api_source = read_python_file(Path("Virus_Scan/models/profiles/api.py"))
    baseline_source = read_python_file(Path("Virus_Scan/models/profiles/baseline.py"))
    vector_source = read_python_file(Path("Virus_Scan/models/profiles/vector_anomaly.py"))
    assert "from Virus_Scan.models.profiles.baseline import" in api_source
    assert "from Virus_Scan.models.profiles.vector_anomaly import vector_baseline_anomaly" in api_source
    assert "from Virus_Scan.models.profiles.api" not in baseline_source
    assert "from Virus_Scan.models.profiles.api" not in vector_source
    assert "def vector_baseline_anomaly" not in baseline_source
    assert "def vector_baseline_anomaly" in vector_source
    assert "def profile_behavior_bucket_validation" not in api_source
    assert "def profile_behavior_bucket_validation" in baseline_source


def test_stage1431_profile_vector_owner_returns_output_affecting_unavailable_evidence():
    baseline = default_profile_vector_statistics()
    baseline["count"] = float("nan")
    record = profile_vector_anomaly.vector_baseline_anomaly(baseline, [1.0] * len(PROFILE_RAW_FEATURE_NAMES))
    assert record["ready"] is False
    assert record["degraded"] is True
    assert record["final_json_must_record"] is True
    assert record["replay_record_required"] is True
