"""Stage 1670 scoring explainability no-hook regression tests."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.detection.scoring.explainability.score_component_builders import (
    as_score_float,
    evidence_terms,
    filetype_context,
    score_component,
)
from Virus_Scan.detection.scoring.explainability.score_component_models import ScoreContribution
from Virus_Scan.detection.scoring.explainability.score_components import build_reproducible_score_explanation


class HostileText:
    str_calls = 0
    repr_calls = 0
    format_calls = 0

    def __str__(self):  # pragma: no cover - failure path only
        type(self).str_calls += 1
        raise AssertionError("hostile __str__ executed")

    def __repr__(self):  # pragma: no cover - failure path only
        type(self).repr_calls += 1
        raise AssertionError("hostile __repr__ executed")

    def __format__(self, spec):  # pragma: no cover - failure path only
        type(self).format_calls += 1
        raise AssertionError("hostile __format__ executed")


class HostileNumeric:
    float_calls = 0
    int_calls = 0

    def __float__(self):  # pragma: no cover - failure path only
        type(self).float_calls += 1
        raise AssertionError("hostile __float__ executed")

    def __int__(self):  # pragma: no cover - failure path only
        type(self).int_calls += 1
        raise AssertionError("hostile __int__ executed")


class HostileIterable:
    iter_calls = 0

    def __iter__(self):  # pragma: no cover - failure path only
        type(self).iter_calls += 1
        raise AssertionError("hostile __iter__ executed")


class HostilePathLike:
    fspath_calls = 0

    def __fspath__(self):  # pragma: no cover - failure path only
        type(self).fspath_calls += 1
        raise AssertionError("hostile __fspath__ executed")

    def __str__(self):  # pragma: no cover - failure path only
        raise AssertionError("hostile path __str__ executed")


class PlainMapping:
    def __init__(self, values):
        self._values = dict(values)


class HostileMappingLike:
    iter_calls = 0

    def __iter__(self):  # pragma: no cover - failure path only
        type(self).iter_calls += 1
        raise AssertionError("hostile mapping-like __iter__ executed")

    def get(self, key, default=None):  # pragma: no cover - failure path only
        raise AssertionError("hostile mapping-like get executed")


def _reset_hostile_counters() -> None:
    HostileText.str_calls = 0
    HostileText.repr_calls = 0
    HostileText.format_calls = 0
    HostileNumeric.float_calls = 0
    HostileNumeric.int_calls = 0
    HostileIterable.iter_calls = 0
    HostilePathLike.fspath_calls = 0
    HostileMappingLike.iter_calls = 0


def test_stage1670_score_component_rejects_hostile_scalars_without_hooks() -> None:
    _reset_hostile_counters()

    component = score_component(
        score_source=HostileText(),
        weight=HostileNumeric(),
        raw_score=HostileNumeric(),
        weighted_score=HostileNumeric(),
        evidence_reference=("safe", HostileText(), HostileIterable()),
        reason=HostileText(),
        engine_context=HostileText(),
        filetype_context_value=HostileText(),
    )
    record = component.to_record()

    assert HostileText.str_calls == 0
    assert HostileText.repr_calls == 0
    assert HostileText.format_calls == 0
    assert HostileNumeric.float_calls == 0
    assert HostileNumeric.int_calls == 0
    assert HostileIterable.iter_calls == 0
    assert record["score_source"] == "score_component_source_unavailable"
    assert record["reason"] == "score_component_reason_unavailable"
    assert "safe" in record["evidence_reference"]
    assert any("unsupported_score_component_evidence_item" in item for item in record["evidence_reference"])
    assert "unsafe_score_component_weight_rejected" in record["evidence_reference"]
    assert "unsafe_score_component_raw_score_rejected" in record["evidence_reference"]
    assert "unsafe_score_component_weighted_score_rejected" in record["evidence_reference"]


def test_stage1670_score_explanation_rejects_hostile_path_profile_and_evidence_without_hooks() -> None:
    _reset_hostile_counters()
    explanation = {
        "layers": {
            "api": {
                "score": HostileNumeric(),
                "hits": ("CreateProcess", HostileText(), HostileIterable()),
                "name": HostileText(),
            }
        },
        "weights": {"api": HostileNumeric()},
        "caps": (
            {
                "name": HostileText(),
                "old_score": HostileNumeric(),
                "new_score": 20.0,
                "reason": HostileText(),
            },
        ),
        "active_layers": HostileText(),
    }

    rebuilt = build_reproducible_score_explanation(
        final_score=HostileNumeric(),
        explanation=explanation,
        path=HostilePathLike(),
        active_profile=HostileText(),
    )

    assert HostileText.str_calls == 0
    assert HostileText.repr_calls == 0
    assert HostileText.format_calls == 0
    assert HostileNumeric.float_calls == 0
    assert HostileNumeric.int_calls == 0
    assert HostileIterable.iter_calls == 0
    assert HostilePathLike.fspath_calls == 0
    flattened_evidence = tuple(
        item
        for component in rebuilt["score_components"]
        for item in component["evidence_reference"]
    )
    assert "unsafe_score_explainability_engine_context_rejected" in rebuilt["score_explainability_evidence"]
    assert any("unsupported_score_component_evidence_item" in item for item in flattened_evidence)
    assert "unsafe_score_component_raw_score_rejected" in flattened_evidence
    assert "unsafe_score_component_weight_rejected" in flattened_evidence
    assert "unsafe_score_component_old_score_rejected" in flattened_evidence
    assert any(component["filetype_context"] == "unknown" for component in rebuilt["score_components"])


def test_stage1670_evidence_terms_rejects_mapping_like_and_unknown_objects_without_hooks() -> None:
    _reset_hostile_counters()

    terms = evidence_terms(HostileMappingLike())
    plain_terms = evidence_terms(PlainMapping({"key": HostileText()}))

    assert HostileMappingLike.iter_calls == 0
    assert HostileText.str_calls == 0
    assert terms == ("unsupported_score_component_evidence_value:HostileMappingLike",)
    assert plain_terms == ("unsupported_score_component_evidence_value:PlainMapping",)


def test_stage1670_score_contribution_constructor_is_no_hook() -> None:
    _reset_hostile_counters()

    contribution = ScoreContribution(
        score_source=HostileText(),
        weight=HostileNumeric(),
        raw_score=HostileNumeric(),
        weighted_score=HostileNumeric(),
        evidence_reference=(HostileText(), HostileIterable()),
        reason=HostileText(),
        engine_context=HostileText(),
        filetype_context=HostileText(),
        confidence_impact=HostileNumeric(),
        malicious_contribution=HostileNumeric(),
        suspicious_contribution=HostileNumeric(),
        benign_contribution=HostileNumeric(),
    )

    assert HostileText.str_calls == 0
    assert HostileText.repr_calls == 0
    assert HostileText.format_calls == 0
    assert HostileNumeric.float_calls == 0
    assert HostileNumeric.int_calls == 0
    assert HostileIterable.iter_calls == 0
    assert contribution.weight == 0.0
    assert any("unsupported_score_contribution_evidence_reference" in item for item in contribution.evidence_reference)


def test_stage1670_filetype_and_float_public_helpers_are_no_hook() -> None:
    _reset_hostile_counters()

    assert as_score_float(HostileNumeric()) == 0.0
    assert filetype_context(HostilePathLike()) == "unknown"

    assert HostileNumeric.float_calls == 0
    assert HostileNumeric.int_calls == 0
    assert HostilePathLike.fspath_calls == 0


def _attach_ast_parents(tree: ast.AST) -> ast.AST:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node
    return tree


def test_stage1670_score_explainability_sources_keep_no_hook_static_contract() -> None:
    paths = (
        Path("Virus_Scan/detection/scoring/explainability/score_component_builders.py"),
        Path("Virus_Scan/detection/scoring/explainability/score_component_models.py"),
        Path("Virus_Scan/detection/scoring/explainability/score_components.py"),
    )
    forbidden_calls = {"str", "repr", "format", "float", "int", "vars"}
    for path in paths:
        tree = _attach_ast_parents(ast.parse(path.read_text(encoding="utf-8")))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                assert isinstance(getattr(node, "parent", None), ast.Module), f"nested import restored in {path}:{node.lineno}"
            if path.name in {"score_component_builders.py", "score_component_models.py"} and isinstance(node, ast.JoinedStr):
                raise AssertionError(f"f-string restored in {path}:{node.lineno}")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden_calls, f"raw {node.func.id}() restored in {path}:{node.lineno}"
        source = path.read_text(encoding="utf-8")
        if path.name == "score_component_models.py":
            forbidden = (
                'reason=f"unsafe_score_contribution_{field_name}_rejected",',
                'non_finite_reason=f"nonfinite_score_contribution_{field_name}",',
                'out.append(f"{reason}:{no_hook_type_name(item)}")',
            )
            assert [snippet for snippet in forbidden if snippet in source] == []
        assert "os.fspath" not in source
        assert "object.__getattribute__" not in source
