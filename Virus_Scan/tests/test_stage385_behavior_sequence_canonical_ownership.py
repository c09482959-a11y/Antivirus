import inspect

from Virus_Scan.detection import tags
from Virus_Scan.detection.models import chain as detection_chain
from Virus_Scan.models import behavior_sequence_contract as contract


def test_behavior_sequence_contract_exposes_single_canonical_signature():
    signature = inspect.signature(contract.canonical_behavior_event_name)
    assert tuple(signature.parameters) == ("value",)


def test_detection_no_longer_reexports_model_owned_behavior_sequence_admission():
    assert not hasattr(tags, "_canonical_behavior_event_name")
    assert "_canonical_behavior_event_name" not in tags.__all__
    assert not hasattr(detection_chain, "canonical_behavior_event_name")
    assert "canonical_behavior_event_name" not in detection_chain.__all__


def test_model_owned_behavior_sequence_admission_remains_canonical():
    assert contract.canonical_behavior_event_name("process_exec") == "process_exec"
    assert contract.canonical_behavior_event_name("url_present") == ""
