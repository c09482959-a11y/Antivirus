import inspect

from Virus_Scan.models import profiles
from Virus_Scan.detection.api import routing_contracts, tags_contracts
from Virus_Scan.detection.correlation.multi_signal import model_context
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_behavior_vector_owned_only_by_profile_model():
    assert hasattr(profiles, "behavior_vector_from_scan")
    assert not hasattr(model_context, "behavior_vector_from_scan")
    source = inspect.getsource(model_context)
    assert "def behavior_vector_from_scan" not in source


def test_detection_public_api_no_longer_reexports_model_vector():
    assert "behavior_vector_from_scan" not in routing_contracts.__all__
    assert "behavior_vector_from_scan" not in tags_contracts.__all__
    assert not hasattr(routing_contracts, "behavior_vector_from_scan")
    assert not hasattr(tags_contracts, "behavior_vector_from_scan")


def test_profile_behavior_vector_contract_still_returns_bounded_vector():
    vector = profiles.behavior_vector_from_scan(
        "renpy",
        "sample.rpy",
        tags=physical_tag_evidence(("network_download", "process_exec")),
    )

    assert vector
    assert all(0.0 <= float(value) <= 1.0 for value in vector)
