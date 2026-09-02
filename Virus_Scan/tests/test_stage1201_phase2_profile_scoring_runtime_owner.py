from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.runtime.profile_scoring_state import ProfileScoringState, profile_scoring_state



def test_profile_scoring_state_is_runtime_owned_not_model_owned() -> None:
    assert Path("Virus_Scan/runtime/profile_scoring_state.py").exists()
    assert not Path("Virus_Scan/models/profile_state.py").exists()
    profiles_source = read_python_file(Path("Virus_Scan/models/profiles/api.py"))
    routing_source = read_python_file(Path("Virus_Scan/routing/engine_detect.py"))
    assert "Virus_Scan.runtime.profile_scoring_state" in profiles_source
    assert "Virus_Scan.runtime.profile_scoring_state" not in routing_source
    assert "profile_scoring_state" in routing_source
    assert "Virus_Scan.runtime.api" in routing_source
    assert "Virus_Scan.models.profile_state" not in profiles_source
    assert "Virus_Scan.models.profile_state" not in routing_source


def test_profile_scoring_state_still_detaches_mutable_input_and_output() -> None:
    state = ProfileScoringState()
    source = {"renpy": {"weights": {"tag": [1.0]}}}
    returned = state.freeze(source)
    source["renpy"]["weights"]["tag"].append(99.0)
    returned["renpy"]["weights"]["tag"].append(42.0)
    snapshot = state.snapshot()
    snapshot["renpy"]["weights"]["tag"].append(100.0)
    assert state.get_profile("renpy") == {"weights": {"tag": [1.0]}}


def test_profile_scoring_state_singleton_is_runtime_public_contract() -> None:
    state = profile_scoring_state()
    state.clear()
    assert state.is_frozen() is False
    state.freeze({"other": {"weights": {"tag": [0.5]}}})
    assert state.get_profile("other") == {"weights": {"tag": [0.5]}}
    state.clear()
