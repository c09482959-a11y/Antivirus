from __future__ import annotations

import json
import math
from collections.abc import Mapping

import pytest

from Virus_Scan.models.contracts.model_evidence import (
    make_model_evidence_record,
    materialize_model_evidence_record,
)
from Virus_Scan.models.contracts.model_failure import (
    make_model_failure_record,
    materialize_model_failure_record,
)
from Virus_Scan.models.contracts.model_feature_bundle import (
    make_model_feature_bundle,
    materialize_model_feature_bundle,
)


def _assert_json_strict(value: object) -> None:
    json.dumps(value, allow_nan=False, sort_keys=True)


def test_stage1309_feature_bundle_materializer_projects_nonfinite_to_unavailable_evidence() -> None:
    source = {
        "markov_probability": math.inf,
        "nested": {"temporal_confidence": math.nan},
        "vector": [0.2, -math.inf],
    }
    bundle = make_model_feature_bundle(source, model_version="stage1309_feature_contract_v1")

    source["nested"]["temporal_confidence"] = 0.9
    assert bundle["markov_probability"] is None
    assert bundle["markov_probability_unavailable_reason"] == "non_finite_model_feature"
    assert isinstance(bundle["nested"], Mapping)
    with pytest.raises(TypeError):
        bundle["nested"]["temporal_confidence"] = 0.1  # type: ignore[index]

    materialized = materialize_model_feature_bundle(bundle)

    assert materialized["nested"]["temporal_confidence"] is None
    assert materialized["nested"]["temporal_confidence_unavailable_reason"] == "non_finite_model_feature"
    assert materialized["vector"][1]["value"] is None
    assert materialized["vector"][1]["unavailable_reason"] == "non_finite_model_feature"
    _assert_json_strict(materialized)


def test_stage1309_model_evidence_materializer_projects_nonfinite_to_unavailable_evidence() -> None:
    evidence = make_model_evidence_record(
        {
            "graph_influence": math.inf,
            "relationships": {"edge_weight": math.nan},
            "cluster_vector": (0.1, -math.inf),
        },
        model_name="graph",
        evidence_type="relationship_features",
        model_version="stage1309_evidence_contract_v1",
    )

    materialized = materialize_model_evidence_record(evidence)

    assert materialized["graph_influence"] is None
    assert materialized["graph_influence_unavailable_reason"] == "non_finite_model_evidence"
    assert materialized["relationships"]["edge_weight"] is None
    assert materialized["relationships"]["edge_weight_unavailable_reason"] == "non_finite_model_evidence"
    assert materialized["cluster_vector"][1]["unavailable_reason"] == "non_finite_model_evidence"
    _assert_json_strict(materialized)


def test_stage1309_model_failure_details_materializer_projects_nonfinite_to_unavailable_evidence() -> None:
    failure = make_model_failure_record(
        model_name="adaptive_scoring",
        failure_type="computation_failure",
        reason="non_finite_model_metric",
        affected_fields=("score",),
        details={"raw_logit": math.inf, "nested": {"confidence": math.nan}},
        model_version="stage1309_failure_contract_v1",
    )

    materialized = materialize_model_failure_record(failure)

    assert materialized["details"]["raw_logit"] is None
    assert materialized["details"]["raw_logit_unavailable_reason"] == "non_finite_model_failure_detail"
    assert materialized["details"]["nested"]["confidence"] is None
    assert materialized["details"]["nested"]["confidence_unavailable_reason"] == "non_finite_model_failure_detail"
    _assert_json_strict(materialized)
