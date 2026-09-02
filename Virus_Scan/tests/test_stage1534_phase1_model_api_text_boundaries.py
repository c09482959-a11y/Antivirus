"""Stage 1534: public model API contracts must not use raw object text hooks."""
from __future__ import annotations

from Virus_Scan.models.api import clustering_contracts, graph_contracts, profile_contracts, profile_learning_contracts, profile_retention_contracts
from Virus_Scan.models.api.replay_comparison_contracts import compare_model_evidence
from Virus_Scan.models.api.text_boundary import public_api_contract_text


class _HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.str_calls = 0
        obj.strip_calls = 0
        obj.bool_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError("hostile __str__ used")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves caller strip was used
        self.strip_calls += 1
        raise AssertionError("hostile strip used")

    def __bool__(self):  # pragma: no cover - failure proves truthiness probing was used
        self.bool_calls += 1
        raise AssertionError("hostile bool used")


class _HostileObject:
    def __init__(self, label: str) -> None:
        self.label = label
        self.str_calls = 0
        self.bool_calls = 0

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError(f"raw object __str__ used for {self.label}")

    def __bool__(self):  # pragma: no cover - failure proves truthiness probing was used
        self.bool_calls += 1
        raise AssertionError(f"truthiness used for {self.label}")


def _assert_no_text_hooks(*values):
    for value in values:
        assert getattr(value, "str_calls", 0) == 0
        assert getattr(value, "strip_calls", 0) == 0
        assert getattr(value, "bool_calls", 0) == 0


def test_stage1534_shared_public_api_text_boundary_detaches_hostile_str_without_object_str():
    hostile = _HostileText("  stage  ")
    unsupported = _HostileObject("unsupported")

    text, reason = public_api_contract_text(hostile)
    unavailable, unavailable_reason = public_api_contract_text(unsupported, default_text="<unavailable>")

    assert text == "stage"
    assert reason is None
    assert unavailable == "<unavailable>"
    assert unavailable_reason == "unreadable_public_contract_text"
    _assert_no_text_hooks(hostile, unsupported)


def test_stage1534_public_contract_immutable_values_emit_unavailable_evidence_for_unsupported_objects():
    key = _HostileText("model_key")
    unsupported = _HostileObject("public-value")
    helpers = (
        clustering_contracts._immutable_cluster_value,
        graph_contracts._immutable_graph_value,
        profile_contracts._immutable_profile_value,
        profile_learning_contracts._immutable_profile_learning_value,
        profile_retention_contracts._immutable_retention_value,
    )

    for helper in helpers:
        materialized = helper({key: unsupported})
        evidence = materialized["model_key"]
        assert evidence["ready"] is False
        assert evidence["degraded"] is True
        assert evidence["unavailable_reason"] == "unreadable_public_contract_text"
        assert evidence["final_json_must_record"] is True
        assert evidence["replay_record_required"] is True

    _assert_no_text_hooks(key, unsupported)


def test_stage1534_replay_comparison_mismatch_keys_do_not_use_raw_object_str():
    hostile_key = _HostileObject("mismatch-key")

    comparison = compare_model_evidence(
        model_name=_HostileText("profile_model"),
        expected={hostile_key: 1},
        actual={},
        reason=_HostileText(" mismatch "),
    )

    assert comparison["matched"] is False
    assert comparison["reason"] == "mismatch"
    assert "<unreadable__HostileObject>" in comparison["mismatch_fields"]
    _assert_no_text_hooks(hostile_key)
