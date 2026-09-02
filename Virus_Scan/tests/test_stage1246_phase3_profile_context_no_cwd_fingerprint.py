from pathlib import Path

from Virus_Scan.models.profiles import api as profile_api
from Virus_Scan.models.profiles.context import profile_context_container_root
from Virus_Scan.routing import context_container_fingerprints


def test_stage1246_bare_model_node_does_not_fingerprint_process_cwd():
    fingerprint = context_container_fingerprints.container_fingerprint(None, "stage1246_synthetic_node.exe")

    assert fingerprint.engine == "other"
    assert fingerprint.evidence == ("container_root_not_provided",)


def test_stage1246_profile_context_uses_explicit_container_root_only_for_real_parents():
    assert profile_context_container_root("stage1246_synthetic_node.exe") is None

    rooted = profile_context_container_root("Virus_Scan/tests/stage1246_sample.rpy")
    assert rooted == Path("Virus_Scan/tests")


def test_stage1246_profile_context_policy_records_no_container_without_cwd_scan():
    identity = profile_api.contextual_profile_learning_policy("stage1246_synthetic_node.exe")

    assert identity.container_engine == "other"
    assert "container_root_not_provided" in identity.fingerprint_evidence
    assert identity.baseline_key
