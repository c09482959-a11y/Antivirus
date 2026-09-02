from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.models import profiles
from Virus_Scan.models.profiles import common as profile_common
from Virus_Scan.models.profiles import learning as profile_learning



def test_stage1432_profile_learning_owner_is_explicit_package_module():
    assert Path("Virus_Scan/models/profiles/learning.py").exists()
    assert Path("Virus_Scan/models/profiles/common.py").exists()
    assert profiles.behavior_vector_from_scan.__module__ == "Virus_Scan.models.profiles.learning"
    assert profiles.canonical_profile_learning_flow.__module__ == "Virus_Scan.models.profiles.learning"
    assert profiles.real_ordered_event_names.__module__ == "Virus_Scan.models.profiles.learning"
    assert not hasattr(profiles, "detect_profile_chains")
    assert Path("Virus_Scan/models/profiles/chain_records.py").exists()


def test_stage1432_profile_learning_has_no_api_back_import_cycle():
    api_source = read_python_file(Path("Virus_Scan/models/profiles/api.py"))
    learning_source = read_python_file(Path("Virus_Scan/models/profiles/learning.py"))
    common_source = read_python_file(Path("Virus_Scan/models/profiles/common.py"))
    assert "from Virus_Scan.models.profiles.learning import" in api_source
    assert "from Virus_Scan.models.profiles.api" not in learning_source
    assert "from Virus_Scan.models.profiles.api" not in common_source
    assert "def behavior_vector_from_scan" not in api_source
    assert "def canonical_profile_learning_flow" not in api_source
    assert "def behavior_vector_from_scan" in learning_source
    assert "def canonical_profile_learning_flow" in learning_source


def test_stage1432_common_helpers_reject_hostile_iterables_without_hooks_or_truthiness():
    class HostileIterable:
        touched = 0

        def __bool__(self):
            type(self).touched += 1
            raise AssertionError("truthiness must not be probed")

        def __iter__(self):
            type(self).touched += 1
            raise AssertionError("iteration must not be probed")

    values, reason = profile_common.profile_public_ordered_events(
        HostileIterable(), "malformed_profile_learning_flow"
    )
    assert reason == "malformed_profile_learning_flow"
    assert values == ()
    assert HostileIterable.touched == 0


def test_stage1432_learning_owner_still_returns_degraded_vector_evidence_for_malformed_inputs():
    class BrokenIterable:
        def __bool__(self):
            raise AssertionError("truthiness must not be probed")

        def __iter__(self):
            raise TypeError("broken iterator")

    record = profile_learning.behavior_vector_from_scan(
        "renpy", "sample.rpy", BrokenIterable(),
    )
    assert record["ready"] is False
    assert record["degraded"] is True
    assert record["final_json_must_record"] is True
    assert record["replay_record_required"] is True
