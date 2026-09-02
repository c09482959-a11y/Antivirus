"""Stage2023 publication model-evidence no-hook regression coverage."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from Virus_Scan.publication.model_evidence_projection.assembly import (
    build_model_evidence_final_json_fields,
)
from Virus_Scan.publication.model_evidence_projection.safe_mapping import safe_mapping_get

ROOT = Path(__file__).resolve().parents[1]
PROJECTION_ROOT = ROOT / "publication" / "model_evidence_projection"
CONTAINER_TYPE_NAMES = ("Mapping", "list", "tuple", "set", "frozenset")


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, key: Any) -> Any:  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("publication must not call caller-owned mapping getitem")

    def __iter__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("publication must not call caller-owned mapping iter")

    def __len__(self) -> int:  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("publication must not call caller-owned mapping len")

    def keys(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("publication must not call caller-owned mapping keys")

    def get(self, key: Any, replacement: Any = None) -> Any:  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("publication must not call caller-owned mapping get")


class HostileList(list):
    touched = 0

    def __iter__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("publication must not call caller-owned sequence iter")


class HostileLookupKey:
    touched = 0
    armed = False

    def __hash__(self) -> int:
        if type(self).armed:
            type(self).touched += 1
            raise AssertionError("publication must not re-hash caller-owned keys")
        return 2023

    def __eq__(self, other: Any) -> bool:  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("publication must not compare caller-owned keys")

    def __str__(self) -> str:  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("publication must not stringify caller-owned keys")

    def __repr__(self) -> str:  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise AssertionError("publication must not repr caller-owned keys")


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _container_type_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Tuple):
        return tuple(_name(item) for item in node.elts)
    return (_name(node),)


def test_stage2023_safe_mapping_get_has_no_default_alias_route() -> None:
    tree = ast.parse(_source(PROJECTION_ROOT / "safe_mapping.py"))
    functions = tuple(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef))
    safe_get = next(node for node in functions if node.name == "safe_mapping_get")

    assert safe_get.args.vararg is None
    assert safe_get.args.kwarg is None
    assert "**named_replacements" not in _source(PROJECTION_ROOT / "safe_mapping.py")


def test_stage2023_projection_consumers_use_owned_container_predicates() -> None:
    offenders: list[str] = []
    for path in sorted(PROJECTION_ROOT.glob("*.py")):
        if path.name in {"safe_mapping.py", "safe_mapping_primitives.py"}:
            continue
        tree = ast.parse(_source(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _name(node.func) != "isinstance" or len(node.args) < 2:
                continue
            names = _container_type_names(node.args[1])
            if any(name in CONTAINER_TYPE_NAMES for name in names):
                offenders.append(str(path.relative_to(ROOT)) + ":" + str(node.lineno))

    assert offenders == []


def test_stage2023_model_evidence_projection_rejects_hostile_containers_without_hooks() -> None:
    HostileMapping.touched = 0
    HostileList.touched = 0
    HostileLookupKey.touched = 0
    HostileLookupKey.armed = False
    hostile_key = HostileLookupKey()
    record = {
        "feature_probabilities": {"markov": 0.25, hostile_key: "opaque"},
        "model_evidence": {
            "feature_probabilities": {"graph": 0.5},
            "unavailable_reasons": HostileMapping(),
        },
        "adaptive_learning": {
            "feature_probabilities": HostileList(({"temporal": 0.2},)),
        },
        "model_failure": HostileList(({"model_name": "x", "failure_type": "y", "reason": "z"},)),
    }
    HostileLookupKey.armed = True

    fields = build_model_evidence_final_json_fields(record)

    evidence = fields["model_evidence"]
    unavailable = evidence["unavailable_reasons"]
    failure_reasons = tuple(failure["reason"] for failure in evidence["model_failures"])
    assert HostileMapping.touched == 0
    assert HostileList.touched == 0
    assert HostileLookupKey.touched == 0
    assert unavailable["model_evidence.unavailable_reasons"] == "unreadable_model_evidence_mapping"
    assert unavailable["adaptive_learning.feature_probabilities"] == "non_mapping_feature_probability_record"
    assert unavailable["model_failure"] == "non_mapping_model_failure_record"
    assert unavailable["feature_probabilities.<HostileLookupKey>"] == "unknown_model_probability_field"
    assert "non_mapping_feature_probability_record" in failure_reasons
    assert "non_mapping_model_failure_record" in failure_reasons
    assert "unknown_model_probability_field" in failure_reasons
    assert safe_mapping_get(HostileMapping(), "missing", replacement="absent") == "absent"
