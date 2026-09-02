import pytest

from Virus_Scan.detection.contracts.filetype_context import (
    filetype_validation_context,
    get_global_filetype_info,
)


def test_stage1356_filetype_context_buckets_are_sorted_immutable_tuples() -> None:
    context = filetype_validation_context("media", "soundtrack.ogg")

    high = context["high_risk_buckets"]
    rare = context["rare_buckets"]
    normal = context["normal_buckets"]

    assert isinstance(high, tuple)
    assert isinstance(rare, tuple)
    assert isinstance(normal, tuple)
    assert high == tuple(sorted(high))
    assert rare == tuple(sorted(rare))
    assert normal == tuple(sorted(normal))
    assert {"persistence", "credential", "injection"}.issubset(high)

    with pytest.raises(AttributeError):
        high.add("caller_mutation")  # type: ignore[attr-defined]


def test_stage1356_global_filetype_info_does_not_leak_mutable_bucket_sets() -> None:
    info = get_global_filetype_info("image.png")

    assert isinstance(info["high_risk_buckets"], tuple)
    assert isinstance(info["rare_buckets"], tuple)
    assert isinstance(info["normal_buckets"], tuple)
    assert info["high_risk_buckets"] == tuple(sorted(info["high_risk_buckets"]))
    assert "entropy_or_packing" in info["normal_buckets"]

    with pytest.raises(AttributeError):
        info["normal_buckets"].add("caller_mutation")  # type: ignore[attr-defined]
