from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.publication.model_evidence_projection.assembly import final_model_evidence_fields
from Virus_Scan.publication.model_evidence_projection.constants import MODEL_EVIDENCE_WRITER_VERSION

_ASSEMBLY_PATH = Path(__file__).resolve().parents[2] / "Virus_Scan/publication/model_evidence_projection/assembly.py"


class _ReturnVisitor(ast.NodeVisitor):
    def __init__(self, target: str) -> None:
        self.target = target
        self.in_target = False
        self.empty_dict_returns: list[int] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous = self.in_target
        self.in_target = node.name == self.target
        self.generic_visit(node)
        self.in_target = previous

    def visit_Return(self, node: ast.Return) -> None:
        if self.in_target and isinstance(node.value, ast.Dict) and not node.value.keys:
            self.empty_dict_returns.append(node.lineno)
        self.generic_visit(node)


def test_stage1721_empty_model_evidence_fields_remain_absent_without_literal_empty_return() -> None:
    assert final_model_evidence_fields({}) == {}

    compact = compact_result_record(
        {
            "file": "empty-model-evidence.exe",
            "path": "empty-model-evidence.exe",
            "classification": "clean",
            "score": 0.0,
            "model_evidence": "",
        }
    )
    assert "model_evidence" not in compact


def test_stage1721_failure_model_evidence_fields_still_force_final_json_and_replay_records() -> None:
    evidence = {"unavailable_reasons": {"model_evidence": "non_mapping_model_evidence_record"}}

    projected = final_model_evidence_fields(evidence)

    assert projected["model_evidence"]["writer_version"] == MODEL_EVIDENCE_WRITER_VERSION
    assert projected["model_evidence"]["final_json_must_record"] is True
    assert projected["model_evidence"]["replay_record_required"] is True


def test_stage1721_final_model_evidence_fields_has_no_literal_empty_dict_return_branch() -> None:
    tree = ast.parse(_ASSEMBLY_PATH.read_text(encoding="utf-8"), filename=str(_ASSEMBLY_PATH))
    visitor = _ReturnVisitor("final_model_evidence_fields")
    visitor.visit(tree)

    assert visitor.empty_dict_returns == []
