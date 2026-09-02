from pathlib import Path

import pytest

from Virus_Scan.utils import entropy, fast_assets, media_stego, pathing, probability, reference_url_policy, stages
from Virus_Scan.utils import tagging, text_match, text_validation
from Virus_Scan.contracts.artifact_read_snapshot import read_artifact_prefix


class HostileUtilsValue:
    touched = []

    @classmethod
    def reset(cls):
        cls.touched.clear()

    def __str__(self):
        type(self).touched.append("__str__")
        return "hostile"

    def __repr__(self):
        type(self).touched.append("__repr__")
        return "hostile"

    def __format__(self, spec):
        type(self).touched.append("__format__")
        return "hostile"

    def __bool__(self):
        type(self).touched.append("__bool__")
        return True

    def __iter__(self):
        type(self).touched.append("__iter__")
        return iter(())

    def __hash__(self):
        type(self).touched.append("__hash__")
        return 1

    def __eq__(self, other):
        type(self).touched.append("__eq__")
        return False

    def __lt__(self, other):
        type(self).touched.append("__lt__")
        return False

    def __float__(self):
        type(self).touched.append("__float__")
        return 99.0

    def __int__(self):
        type(self).touched.append("__int__")
        return 99

    def __fspath__(self):
        type(self).touched.append("__fspath__")
        return "hostile"

    def __bytes__(self):
        type(self).touched.append("__bytes__")
        return b"hostile"


class HostileUtilsMapping:
    def get(self, key, default=None):
        HostileUtilsValue.touched.append("mapping.get")
        return default

    def items(self):
        HostileUtilsValue.touched.append("mapping.items")
        return ()

    def values(self):
        HostileUtilsValue.touched.append("mapping.values")
        return ()

    def __bool__(self):
        HostileUtilsValue.touched.append("mapping.__bool__")
        return True


def test_stage2022_utils_numeric_text_and_mapping_boundaries_reject_hostile_values_without_hooks():
    hostile = HostileUtilsValue()
    HostileUtilsValue.reset()

    assert entropy.shannon_entropy_bytes(hostile) == 0.0
    assert entropy.entropy_from_counts([hostile, 1], hostile) == 0.0
    assert entropy.tag_entropy([hostile]) == 0.0
    assert probability.safe_clamp(hostile) == 0.0
    assert probability.calibrated_sigmoid_probability(hostile) == 0.0
    assert probability.safe_logit_probability(hostile) == 0.0
    assert stages.choose_effective_stage("unknown", HostileUtilsMapping()) == "unknown"

    assert HostileUtilsValue.touched == []


def test_stage2022_utils_path_asset_and_reference_boundaries_reject_hostile_values_without_hooks():
    hostile = HostileUtilsValue()
    HostileUtilsValue.reset()

    assert fast_assets.sniff_recovered_rpgm_payload_type(hostile, ext=hostile) == ("encrypted_asset", [])
    assert fast_assets.probe_rpgm_encrypted_header(hostile, header=hostile, ext=hostile) == {
        "is_rpgm_encrypted": False,
    }
    assert fast_assets.validated_embedded_payload_hits(hostile, min_offset=hostile) == []
    assert media_stego.image_is_jpeg(path=hostile) is False
    assert media_stego.bits_to_bytes([hostile, 1, True]) == b""
    with pytest.raises(ValueError, match="artifact_prefix_read_limit_invalid"):
        read_artifact_prefix(hostile, hostile)
    assert pathing.scan_path_text(hostile) == ""
    assert reference_url_policy.suppress_reference_url_false_positives(
        [hostile, "network_activity"],
        path=hostile,
        strings_blob=hostile,
    )
    assert tagging.ordered_unique_tags([hostile]) == [
        tagging.TAG_NORMALIZATION_FAILURE_EVIDENCE,
        tagging.DETECTION_STAGE_DEGRADED_TAG,
    ]
    assert text_match.has_any_text(hostile, [hostile]) is False
    assert text_validation.tag_validation_text(hostile) == ""

    assert HostileUtilsValue.touched == []


def test_stage2022_utils_sources_no_longer_contain_repaired_hookable_patterns():
    sources = {
        "Virus_Scan/utils/entropy.py": (
            "counts.values()",
            "float(total or 0)",
            "float(c or 0)",
        ),
        "Virus_Scan/utils/fast_assets.py": (
            "legacy global",
            "str(value or \"\")",
            "str(ext or \"\")",
            "int(max_parents)",
            "int(max_bytes)",
        ),
        "Virus_Scan/utils/pathing.py": ("int(max_size or 8192)",),
        "Virus_Scan/utils/probability.py": (
            "private fallback helper",
            "return safe_clamp(1.0 / (1.0 + z))",
            "return safe_clamp(z / (1.0 + z))",
            "p = safe_clamp(probability, 1e-5, 1.0 - 1e-5)",
        ),
        "Virus_Scan/utils/reference_url_policy.py": ("Path(str(path))",),
        "Virus_Scan/utils/stages.py": (
            "(identity or {}).get",
            "float((identity or {}).get",
            "str((identity or {}).get",
        ),
        "Virus_Scan/utils/tagging.py": ("legacy shared-state",),
        "Virus_Scan/utils/text_match.py": ("except IO_CONFIGURATION_ERRORS",),
    }

    offenders = {}
    for path_text, snippets in sources.items():
        source = Path(path_text).read_text(encoding="utf-8")
        present = [snippet for snippet in snippets if snippet in source]
        if present:
            offenders[path_text] = present

    assert offenders == {}
