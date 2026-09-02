from types import MappingProxyType

from Virus_Scan.scanners import image_tags
from Virus_Scan.scanners.image_tags import rewrite_stego_tags, stego_tag_rewrite_map


def test_stage1003_image_stego_rewrite_policy_is_immutable_snapshot():
    policy = image_tags._WEAK_IMAGE_STEGO_TAG_REWRITE
    assert isinstance(policy, MappingProxyType)
    assert policy["possible_lsb_stego"] == "weak_image_stego_observation"
    try:
        policy["possible_lsb_stego"] = "mutated"
    except TypeError:
        pass
    else:  # pragma: no cover - regression guard
        raise AssertionError("image stego rewrite policy must reject runtime mutation")
    assert policy["possible_lsb_stego"] == "weak_image_stego_observation"


def test_stage1003_image_stego_policy_copy_mutation_does_not_change_scanner_behavior():
    policy_copy = stego_tag_rewrite_map()
    assert policy_copy["stego_payload_suspect"] == "stego_candidate_observation"
    policy_copy["stego_payload_suspect"] = "mutated"
    assert stego_tag_rewrite_map()["stego_payload_suspect"] == "stego_candidate_observation"
    assert rewrite_stego_tags(["stego_payload_suspect"]) == ["stego_candidate_observation"]
