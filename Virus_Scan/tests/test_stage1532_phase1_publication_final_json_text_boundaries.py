from __future__ import annotations

from Virus_Scan.publication.json_finalization.base_projection import (
    bounded_dict,
    bounded_probability_mapping,
    bounded_signal_value,
    canonical_chain_list,
    canonical_tag_list,
    record_sample_id,
    stable_record_path,
)


class HostileText:
    def __str__(self) -> str:  # pragma: no cover - failure path is the contract
        raise RuntimeError("hostile text hook must not escape")

    def __bool__(self) -> bool:  # pragma: no cover - truthiness must not be probed
        raise AssertionError("truthiness must not be probed")


class HostileTextKey:
    def __str__(self) -> str:  # pragma: no cover - failure path is the contract
        raise RuntimeError("hostile key text hook must not escape")

    def __bool__(self) -> bool:  # pragma: no cover - truthiness must not be probed
        raise AssertionError("truthiness must not be probed")


def test_stage1532_final_json_identity_fields_do_not_probe_hostile_text_hooks() -> None:
    record = {"input_file_path": HostileText(), "filename": HostileText(), "sample_id": HostileText()}

    assert stable_record_path(record) == "<HostileText final_json_text_unavailable>"
    sample_id = record_sample_id(record)

    assert sample_id.startswith("path_")


def test_stage1532_final_json_tag_and_chain_lists_materialize_unavailable_text_explicitly() -> None:
    hostile = HostileText()

    tags = canonical_tag_list(["safe", hostile])
    chains = canonical_chain_list([hostile, "chain.safe"])

    assert "safe" in tags
    assert "chain.safe" in chains
    assert any("final_json_text_unavailable" in item for item in tags)
    assert any("final_json_text_unavailable" in item for item in chains)


def test_stage1532_probability_mapping_key_text_failure_is_explicit_not_clean_empty() -> None:
    projected = bounded_probability_mapping({HostileTextKey(): 0.75})

    assert list(projected) == ["_unavailable_key_0"]
    assert projected["_unavailable_key_0"]["model_signal_projection_failed"] is True
    assert projected["_unavailable_key_0"]["reason"] == "final_json_key_text_unavailable"


def test_stage1532_bounded_dict_and_signal_value_do_not_stringify_hostile_objects() -> None:
    key = HostileTextKey()
    value = HostileText()

    projected = bounded_dict({key: value, "safe_value": value})
    signal = bounded_signal_value(value)

    assert projected["_unavailable_key_0"]["reason"] == "final_json_key_text_unavailable"
    assert projected["safe_value"]["model_signal_projection_failed"] is True
    assert projected["safe_value"]["reason"] == "final_json_text_unavailable"
    assert signal["model_signal_projection_failed"] is True
    assert signal["reason"] == "final_json_text_unavailable"
