from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.detection.scoring.yara import context_evidence
from Virus_Scan.tests.support.canonical_yara_fixtures import canonical_test_yara_result


def test_stage1135_yara_context_has_no_probability_contract_tables() -> None:
    module_path = Path(context_evidence.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    forbidden = {
        "RELIABILITY_TO_NUMERIC",
        "EVIDENCE_STRENGTH_TO_LIKELIHOOD",
        "YARA_RULE_CONFIDENCE_KEYWORDS",
        "CORRELATION_GROUP_KEYWORDS",
    }
    assigned = {
        target.id
        for node in tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        if isinstance(target, ast.Name)
    }
    assert not assigned.intersection(forbidden)


def test_stage1135_yara_context_is_explicitly_zero_authority() -> None:
    context = context_evidence.generic_yara_evidence_context(
        canonical_test_yara_result(rule_name="MimikatzCredentialDump")
    )
    record = context.to_record()
    assert record["probability_authority"] is False
    assert record["probability_unavailable_reason"] == "yara_production_calibration_unavailable"
    assert "confidence" not in record
    assert "posterior" not in record
    assert "calibrated_score" not in record
