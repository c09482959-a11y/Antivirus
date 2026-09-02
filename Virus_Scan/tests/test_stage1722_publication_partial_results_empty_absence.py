from __future__ import annotations

import ast
import json
from pathlib import Path

from Virus_Scan.publication.json_finalization.partial_results import (
    PARTIAL_RECOVERY_EVIDENCE_KEY,
    load_partial_results,
    recover_results_from_partial,
)

_PARTIAL_RESULTS_PATH = Path(__file__).resolve().parents[2] / "Virus_Scan/publication/json_finalization/partial_results.py"


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


def test_stage1722_missing_partial_result_remains_legitimate_empty_absence_without_literal_return(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"

    assert load_partial_results(str(output)) == {}
    assert recover_results_from_partial(str(output), {"current": {"classification": "clean"}}) == {
        "current": {"classification": "clean"}
    }


def test_stage1722_empty_partial_result_remains_legitimate_empty_absence(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"
    Path(str(output) + ".partial").write_text("", encoding="utf-8")

    assert load_partial_results(str(output)) == {}


def test_stage1722_malformed_partial_result_still_emits_explicit_recovery_evidence(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"
    Path(str(output) + ".partial").write_text(json.dumps(["not", "mapping"]), encoding="utf-8")

    result = recover_results_from_partial(str(output), {"current": {"classification": "clean"}})

    assert result["current"] == {"classification": "clean"}
    evidence = result[PARTIAL_RECOVERY_EVIDENCE_KEY]
    assert evidence["partial_result_recovery_failed"] is True
    assert evidence["reason"] == "partial_result_not_mapping"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_record"] is True


def test_stage1722_load_partial_results_has_no_literal_empty_dict_return_branch() -> None:
    tree = ast.parse(_PARTIAL_RESULTS_PATH.read_text(encoding="utf-8"), filename=str(_PARTIAL_RESULTS_PATH))
    visitor = _ReturnVisitor("load_partial_results")
    visitor.visit(tree)

    assert visitor.empty_dict_returns == []
