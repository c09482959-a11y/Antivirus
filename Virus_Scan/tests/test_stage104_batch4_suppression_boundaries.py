from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
import pytest

from Virus_Scan.runtime.structured_failures import clear_failure_records, record_suppressed_failure, failure_snapshot
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.full_analysis.score_explained import (
    ScoreExplainedRequest,
    score_explained,
)
from Virus_Scan.cli.exit_codes import score_from_result

def test_suppressed_queue_integrity_failure_is_marked_unsafe_and_fatal():
    clear_failure_records()
    tag = record_suppressed_failure("queue_write_json_replace", ValueError("failure_info missing"), domain="queue")
    assert tag == "failure_queue_queue_write_json_replace"
    records = failure_snapshot()["records"]
    assert len(records) == 1
    rec = records[0]
    assert rec["suppressed"] is True
    assert rec["fatal"] is True
    assert rec["unsafe_to_continue"] is True
    assert rec["continuation_policy"] in {"unsafe_integrity_boundary", "unsafe_exception_at_integrity_boundary"}
    assert rec["fingerprint"]
    assert rec["correlation_id"]
    assert rec["trace_tail"]


def test_optional_probe_suppression_is_not_promoted_to_integrity_fatal():
    clear_failure_records()
    record_suppressed_failure("optional_feature_probe", RuntimeError("missing optional backend"), domain="telemetry")
    rec = failure_snapshot()["records"][0]
    assert rec["suppressed"] is True
    assert rec["fatal"] is False
    assert rec["unsafe_to_continue"] is False
    assert rec["continuation_policy"] == "safe_optional_degrade"


def test_score_explained_exception_fails_closed_with_error_contract():

    class BrokenTag:
        def __str__(self):
            raise RuntimeError("synthetic scoring crash")

    score, explanation = score_explained(ScoreExplainedRequest(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        tags=[BrokenTag()],
        chain_evidence=evaluate_chain_evidence(tags=()),
        yara_evidence=None,
        node="n",
    ))
    assert score == 0.0
    assert explanation["classification"] == "error"
    assert explanation["exit_code"] == 4
    assert explanation["file_failed"] is True
    assert explanation["scan_incomplete"] is True
    assert "score_integrity_failed" in explanation["failure_tags"]


def test_malformed_declared_score_field_does_not_fall_back_to_clean():
    clear_failure_records()
    with pytest.raises(ValueError):
        score_from_result({"score": object(), "layers": {"fallback": {"score": 0}}})
    rec = failure_snapshot()["records"][0]
    assert rec["domain"] == "scoring"
    assert rec["fatal"] is True
    assert rec["unsafe_to_continue"] is True
