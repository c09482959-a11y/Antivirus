from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.publication.json_finalization.base_projection import (
    bounded_dict,
    bounded_signal_value,
    canonical_chain_list,
    canonical_tag_list,
    canonical_text_list,
    record_sample_id,
    stable_record_path,
)


class HostileFinalJsonText:
    touched = 0

    def __str__(self):  # pragma: no cover - failure proves caller text hook ran
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ executed")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __format__ executed")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ executed")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __iter__ executed")


class HostileFinalJsonKey(HostileFinalJsonText):
    pass


def test_stage2002_publication_identity_and_lists_keep_explicit_no_hook_boundaries() -> None:
    HostileFinalJsonText.touched = 0
    value = HostileFinalJsonText()
    record = {"input_file_path": value, "filename": value, "sample_id": value}

    assert stable_record_path(record) == "<HostileFinalJsonText final_json_text_unavailable>"
    assert record_sample_id(record).startswith("path_")
    assert canonical_tag_list(("safe", value)) == [
        "<HostileFinalJsonText final_json_text_unavailable>",
        "safe",
    ]
    assert canonical_chain_list((value, "safe.chain")) == [
        "<HostileFinalJsonText final_json_text_unavailable>",
        "safe.chain",
    ]
    assert canonical_text_list((value, "safe.text")) == [
        "<HostileFinalJsonText final_json_text_unavailable>",
        "safe.text",
    ]
    assert HostileFinalJsonText.touched == 0


def test_stage2002_publication_dict_and_signal_reject_hostile_leafs_without_hooks() -> None:
    HostileFinalJsonText.touched = 0
    HostileFinalJsonKey.touched = 0
    value = HostileFinalJsonText()
    key = HostileFinalJsonKey()

    projected = bounded_dict({key: value, "safe": value})
    signal = bounded_signal_value(value)

    assert projected["_unavailable_key_0"]["reason"] == "final_json_key_text_unavailable"
    assert projected["safe"]["reason"] == "final_json_text_unavailable"
    assert signal["reason"] == "final_json_text_unavailable"
    assert HostileFinalJsonText.touched == 0
    assert HostileFinalJsonKey.touched == 0


def test_stage2002_publication_base_projection_source_removed_direct_fallback_sites() -> None:
    source = read_python_file(Path("Virus_Scan/publication/json_finalization/base_projection.py"))

    forbidden = (
        "safe_projection_text(path)",
        "return f\"<{final_json_type_name(path)} {reason}>\"",
        "safe_projection_text(existing)",
        "safe_projection_text(filename_source)",
        "return f\"path_{digest}\"",
        "safe_projection_text(item)",
        "text = f\"<{final_json_type_name(item)} final_json_text_unavailable>\"",
        "items.append(f\"<{final_json_type_name(item)} final_json_text_unavailable>\"[:width])",
        "lambda pair: safe_projection_sort_key(pair[0])",
        "out_key, key_reason = safe_json_key_text(key, idx)",
        "safe_bounded_text_value(v, 512)",
        "return safe_bounded_text_value(value, 512)",
    )
    for snippet in forbidden:
        assert snippet not in source
