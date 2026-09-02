import inspect

import pytest

from Virus_Scan.contracts import result_record


class HostileTruthiness:
    def __bool__(self):  # pragma: no cover - must never be called
        raise AssertionError("caller-owned truthiness was probed")

    def __eq__(self, other):  # pragma: no cover - must never be called
        raise AssertionError("caller-owned equality was probed")

    def __str__(self):
        return "hostile-model-evidence"


class HostileReasonKey:
    def __bool__(self):  # pragma: no cover - must never be called
        raise AssertionError("caller-owned key truthiness was probed")

    def __eq__(self, other):  # pragma: no cover - must never be called
        raise AssertionError("caller-owned key equality was probed")

    def __hash__(self):
        return 1501

    def __str__(self):
        return "markov_unavailable_reason"


class HostileFeatureKey(HostileReasonKey):
    def __str__(self):
        return "markov_probability"


def test_result_record_rejects_non_mapping_model_evidence_without_truthiness_or_equality_probe():
    with pytest.raises(ValueError, match="non-json value|model evidence record must be an object"):
        result_record.validate_evidence_object_invariants(
            {"model_evidence": HostileTruthiness()},
            context="stage1501",
        )


def test_feature_probability_container_shape_rejects_hostile_non_mapping_without_blank_comparison():
    with pytest.raises(ValueError, match="feature probabilities record must be an object|non-json value"):
        result_record.validate_evidence_object_invariants(
            {"feature_probabilities": HostileTruthiness()},
            context="stage1501",
        )


def test_unavailable_reason_keys_do_not_probe_caller_owned_truthiness():
    assert result_record.validate_evidence_object_invariants(
        {
            "model_evidence": {
                "unavailable_reasons": {HostileReasonKey(): "cold start"},
            }
        },
        context="stage1501",
    ) is True


def test_feature_probability_keys_do_not_probe_caller_owned_truthiness():
    assert result_record.validate_evidence_object_invariants(
        {"feature_probabilities": {HostileFeatureKey(): 0.25}},
        context="stage1501",
    ) is True


def test_result_record_model_evidence_boundary_no_longer_uses_targeted_unsafe_snippets():
    source = inspect.getsource(result_record)
    forbidden = (
        "model_evidence is None or model_evidence == ''",
        "feature_probabilities != ''",
        "feature_probabilities == ''",
        "unavailable_reasons == ''",
        "value is None or value == ''",
        "str(key or '').strip()",
        "str(raw_key or '').strip()",
    )
    for snippet in forbidden:
        assert snippet not in source
