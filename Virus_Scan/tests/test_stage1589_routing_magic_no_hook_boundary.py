from Virus_Scan.routing.magic import claimed_filetype_category, expected_magic_mismatch
from Virus_Scan.routing.magic_extension_tags import (
    apply_filetype_category_tags,
    apply_magic_mismatch_tags,
    is_rpgm_passive_recovered,
    rpgm_passive_recovery_record,
)


class HostileRoutingValue:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("routing must not stringify hostile values")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("routing must not repr hostile values")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("routing must not format hostile values")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("routing must not truth-test hostile values")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("routing must not iterate hostile values")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("routing must not coerce hostile scores")


class HostileRoutingTags:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("routing must not iterate unknown tag containers")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("routing must not stringify unknown tag containers")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("routing must not repr unknown tag containers")


def test_stage1589_rpgm_recovery_rejects_unknown_tag_container_without_hooks():
    HostileRoutingTags.touched = 0
    tags = HostileRoutingTags()

    record = rpgm_passive_recovery_record(
        ".png",
        "image",
        "rpgm_mv_encrypted_asset",
        tags,
    )

    assert record["recovered"] is False
    assert record["tag_texts"] == frozenset()
    assert record["unavailable_reasons"]["tags"] == "routing_magic_tags_rejected"
    assert is_rpgm_passive_recovered(".png", "image", "rpgm_mv_encrypted_asset", tags) is False
    assert HostileRoutingTags.touched == 0


def test_stage1589_rpgm_recovery_preserves_owned_sequence_with_hostile_item():
    HostileRoutingValue.touched = 0
    hostile = HostileRoutingValue()

    assert is_rpgm_passive_recovered(
        ".png",
        "image",
        "rpgm_mv_encrypted_asset",
        [hostile, "rpgm_encrypted_asset", "rpgm_recovered_magic_png"],
    ) is True
    assert HostileRoutingValue.touched == 0


def test_stage1589_magic_mismatch_and_category_reject_hostile_values_without_hooks():
    HostileRoutingValue.touched = 0
    hostile = HostileRoutingValue()

    assert expected_magic_mismatch(hostile, hostile) is False
    assert claimed_filetype_category(hostile) == "unknown"
    assert HostileRoutingValue.touched == 0


def test_stage1589_magic_tag_emitters_reject_hostile_text_and_scores_without_hooks():
    HostileRoutingValue.touched = 0
    hostile = HostileRoutingValue()
    tags = []

    apply_magic_mismatch_tags(tags, hostile, hostile, mismatch=True, rpgm_recovered=False)
    apply_filetype_category_tags(tags, hostile, hostile, hostile, hostile)

    assert "claimed_ext_unknown" in tags
    assert "actual_magic_unknown" in tags
    assert "claimed_filetype_unknown" in tags
    assert "actual_filetype_unknown" in tags
    assert "filetype_misclassification_score_0" in tags or "extension_magic_confirmed" in tags
    assert HostileRoutingValue.touched == 0
