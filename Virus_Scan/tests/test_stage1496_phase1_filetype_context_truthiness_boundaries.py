
"""Stage 1496: filetype-context policy projection must not truth-test caller policy mappings."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.detection.contracts import filetype_context as ftc
from Virus_Scan.detection.contracts.filetype_context import filetype_validation_context


class HostileBoolMapping(Mapping):
    def __init__(self, data):
        self._data = dict(data)

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def __bool__(self):
        raise RuntimeError("policy mapping truthiness must not be consulted")


class HostileBoolIterable:
    def __init__(self, values):
        self._values = tuple(values)

    def __iter__(self):
        return iter(self._values)

    def __bool__(self):
        raise RuntimeError("policy iterable truthiness must not be consulted")


def test_stage1496_copy_policy_record_detaches_without_mapping_truthiness() -> None:
    record = HostileBoolMapping(
        {
            "execution_capability": "none",
            "normal_buckets": HostileBoolIterable(["entropy_or_packing"]),
            "rare_buckets": HostileBoolIterable(["network"]),
            "high_risk_buckets": HostileBoolIterable(["credential", "evasion"]),
        }
    )

    copied = ftc._copy_policy_record(record, bucket="asset_text_config", extension="json")

    assert copied["execution_capability"] == "none"
    assert copied["normal_buckets"] == ("entropy_or_packing",)
    assert copied["rare_buckets"] == ("network",)
    assert copied["high_risk_buckets"] == ("credential", "evasion")


def test_stage1496_policy_extension_projection_detaches_without_info_truthiness() -> None:
    info = HostileBoolMapping({"extensions": HostileBoolIterable([".rpy", "rpyc"])})

    assert ftc._policy_extensions(info) == frozenset({"rpy", "rpyc"})


def test_stage1496_filetype_context_source_has_no_policy_or_empty_mapping_fallbacks() -> None:
    source = read_python_file(Path("Virus_Scan/detection/contracts/filetype_context.py"))

    assert "record or {}" not in source
    assert "registry_value(\"ENGINE_SPECIFIC_FILETYPE_BUCKETS\", {}) or {}" not in source
    assert "registry_value(\"GLOBAL_COMMON_FILETYPE_BUCKETS\", {}) or {}" not in source
    assert "info or {}" not in source


def test_stage1496_public_filetype_context_preserves_existing_media_policy() -> None:
    context = filetype_validation_context("media", "soundtrack.ogg")

    assert context["active_bucket"] == "asset_audio"
    assert context["execution_capability"] == "none"
    assert "entropy_or_packing" in context["normal_buckets"]
    assert {"credential", "injection", "persistence"}.issubset(context["high_risk_buckets"])
