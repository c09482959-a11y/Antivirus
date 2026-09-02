from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path

from Virus_Scan.models import profiles
from Virus_Scan.models.profiles.request_contracts import ProfileBucketValidationRequest
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.detection.scoring.behavior import bucket_validation as detection_bucket_validation



def test_stage1170_profile_bucket_validation_has_profile_specific_name() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/baseline.py"))
    tree = ast.parse(source)
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    assert "profile_behavior_bucket_validation" in function_names
    assert "behavior_bucket_validation" not in function_names


def test_stage1170_profile_learning_uses_profile_bucket_validation_owner(tmp_path) -> None:
    sample = tmp_path / "clean_sample.rpy"
    sample.write_text("label start:\n    return\n", encoding="utf-8")

    result = profiles.profile_behavior_bucket_validation(
        ProfileBucketValidationRequest(
            "renpy", sample, physical_tag_evidence(("renpy_script_logic",)),
            strings_blob="label start",
        )
    )

    assert result["version"]
    assert result["engine"] == "renpy"
    assert result["records"]
    assert result["allow_learning"] is True


def test_stage1170_detection_bucket_validation_keeps_detection_public_contract(tmp_path) -> None:
    sample = tmp_path / "payload.dll"
    sample.write_bytes(b"MZ" + b"\0" * 64)

    result = detection_bucket_validation.behavior_bucket_validation(
        "unity",
        sample,
        physical_tag_evidence(("process_exec", "network_download")),
        strings_blob="CreateProcess DownloadString",
    )

    assert result["version"]
    assert result["records"]
    assert "profile_behavior_bucket_validation" not in detection_bucket_validation.__all__
