from Virus_Scan.scanners.image import rewrite_stego_tags
from Virus_Scan.scanners.init_parts.scanner_filetype_defaults_init import init_scanner_defaults
from Virus_Scan.runtime.config_values import runtime_value
from Virus_Scan.utils.media_stego import canonical_stego_tag_rewrite_map


def test_stego_rewrite_policy_has_single_canonical_owner():
    policy = canonical_stego_tag_rewrite_map()
    assert policy["possible_lsb_stego"] == "weak_image_stego_observation"
    assert policy["stego_payload_suspect"] == "stego_candidate_observation"
    assert rewrite_stego_tags(["possible_lsb_stego", "stego_payload_suspect"]) == [
        "weak_image_stego_observation",
        "stego_candidate_observation",
    ]


def test_scanner_initializer_function_publishes_canonical_stego_policy():
    init_scanner_defaults()
    published = runtime_value("_WEAK_IMAGE_STEGO_TAG_REWRITE")
    assert published == canonical_stego_tag_rewrite_map()
    assert published["possible_lsb_stego"] == "weak_image_stego_observation"
