from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path
from Virus_Scan.detection.api import tags_contracts
from Virus_Scan.detection.correlation.multi_signal.model_context import detection_behavior_flow_from_sources
from Virus_Scan.models import profiles



def test_detection_model_context_no_longer_claims_canonical_model_flow_public_names():
    source = read_python_file(Path("Virus_Scan/detection/correlation/multi_signal/model_context.py"))
    tree = ast.parse(source)
    function_names = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}

    assert "canonical_behavior_flow_from_sources" not in function_names
    assert "build_canonical_model_context" not in function_names
    assert "detection_behavior_flow_from_sources" in function_names
    assert "build_detection_model_context" in function_names


def test_detection_tag_contract_exports_detection_named_context_not_model_canonical_alias():
    assert "canonical_behavior_flow_from_sources" not in tags_contracts.__all__
    assert "build_canonical_model_context" not in tags_contracts.__all__
    assert "detection_behavior_flow_from_sources" in tags_contracts.__all__
    assert "build_detection_model_context" in tags_contracts.__all__
    assert not hasattr(tags_contracts, "canonical_behavior_flow_from_sources")
    assert not hasattr(tags_contracts, "build_canonical_model_context")


def test_detection_and_model_flow_owners_remain_separate_and_behavior_is_preserved():
    detection_flow = detection_behavior_flow_from_sources(raw_tags=["ignored_unordered"], ordered_events=["api_CreateFile", "api_CreateFile", "tag_network_download"])
    model_flow = profiles.canonical_behavior_flow_from_sources(raw_tags=["ignored_unordered"], ordered_events=["api_CreateFile", "api_CreateFile", "tag_network_download"])

    assert detection_flow == ["createfile", "network_download"]
    assert model_flow == ["api_createfile", "tag_network_download"]
    assert detection_behavior_flow_from_sources is not profiles.canonical_behavior_flow_from_sources
