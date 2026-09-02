from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import python_files_under, read_python_file


from Virus_Scan.scanners.binary_behavior_filetype_model import (
    FiletypeBucketModelRequest,
    filetype_bucket_model_signal,
)
from Virus_Scan.scanners.binary_raw_anchors import binary_raw_dangerous_anchor_hits
from Virus_Scan.utils.tagging import (
    DETECTION_STAGE_DEGRADED_TAG,
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    norm_lower_set,
    normalize_tags,
    ordered_unique_tags,
)


class HostileTag:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify tag")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr tag")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("do not format tag")


class HostileTagContainer:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test tag container")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate tag container")


class HostileLowerTag(str):
    touched = 0

    def lower(self):
        type(self).touched += 1
        raise RuntimeError("do not call string subclass lower")

    def strip(self, *args, **kwargs):
        type(self).touched += 1
        raise RuntimeError("do not call string subclass strip")


def test_stage1693_binary_tag_helpers_reject_hostile_tag_without_string_hooks():
    HostileTag.touched = 0

    normalized = ordered_unique_tags([HostileTag()])

    assert HostileTag.touched == 0
    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in normalized
    assert DETECTION_STAGE_DEGRADED_TAG in normalized
    assert normalize_tags(["Memory_Write", "Memory_Write"]) == ["Memory_Write"]


def test_stage1693_binary_tag_helpers_reject_unknown_container_without_bool_or_iter_hooks():
    HostileTagContainer.touched = 0

    normalized = normalize_tags(HostileTagContainer())
    lowered = norm_lower_set(HostileTagContainer())

    assert HostileTagContainer.touched == 0
    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in normalized
    assert DETECTION_STAGE_DEGRADED_TAG in normalized
    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in lowered
    assert DETECTION_STAGE_DEGRADED_TAG in lowered


def test_stage1693_binary_raw_anchor_hits_do_not_truth_test_or_iterate_hostile_tags():
    HostileTagContainer.touched = 0

    hits = binary_raw_dangerous_anchor_hits(HostileTagContainer())

    assert HostileTagContainer.touched == 0
    assert hits == ()


def test_stage1693_filetype_model_signal_does_not_truth_test_tag_container_or_call_str_subclass_hooks(tmp_path):
    HostileTagContainer.touched = 0
    HostileLowerTag.touched = 0

    result = filetype_bucket_model_signal(FiletypeBucketModelRequest(
        "unity",
        tmp_path / "sample.dll",
        HostileTagContainer(),
        strings_blob="",
        api_calls=(HostileLowerTag("CreateRemoteThread"),),
        ordered_events=(HostileLowerTag("memory_write"),),
    ))

    assert HostileTagContainer.touched == 0
    assert HostileLowerTag.touched == 0
    emitted_tags = {record["tag"] for record in result["records"]}
    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in emitted_tags
    assert DETECTION_STAGE_DEGRADED_TAG in emitted_tags
    assert result["filetype_anomaly"] >= 0.0


def test_stage1793_scanner_binary_tags_wrapper_stays_deleted():
    scanner_files = python_files_under("Virus_Scan/scanners")
    binary_tags_path = "Virus_Scan/scanners/binary_tags.py"

    assert all(path.as_posix() != binary_tags_path for path in scanner_files)
    offenders = [
        path.as_posix()
        for path in scanner_files
        if "Virus_Scan.scanners.binary_tags" in read_python_file(path)
    ]
    assert offenders == []
