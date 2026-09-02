"""Stage2016 publication model-evidence projection no-hook boundary regressions."""

from __future__ import annotations

import ast
from pathlib import Path
from collections.abc import Mapping

from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields
from Virus_Scan.publication.model_evidence_projection.safe_mapping import (
    json_value,
    mapping_readable,
    safe_mapping_get,
    safe_mapping_keys,
    safe_str,
)

ROOT = Path(__file__).resolve().parents[1]
PROJECTION_ROOT = ROOT / "publication" / "model_evidence_projection"
FINALIZATION_ROOT = ROOT / "publication" / "json_finalization"


class HostileText:
    def __str__(self):  # pragma: no cover - must not be called
        raise AssertionError("caller-owned __str__ hook executed")

    def __repr__(self):  # pragma: no cover - must not be called
        raise AssertionError("caller-owned __repr__ hook executed")

    def __format__(self, spec):  # pragma: no cover - must not be called
        raise AssertionError("caller-owned __format__ hook executed")


class HostileDict(dict):
    def keys(self):  # pragma: no cover - must not be called
        raise AssertionError("caller-owned keys hook executed")

    def items(self):  # pragma: no cover - must not be called
        raise AssertionError("caller-owned items hook executed")

    def get(self, key, default=None):  # pragma: no cover - must not be called
        raise AssertionError("caller-owned get hook executed")

    def __contains__(self, key):  # pragma: no cover - must not be called
        raise AssertionError("caller-owned contains hook executed")

    def __iter__(self):  # pragma: no cover - must not be called
        raise AssertionError("caller-owned iter hook executed")


class HostileMapping(Mapping):
    def __getitem__(self, key):  # pragma: no cover - must not be called
        raise AssertionError("caller-owned getitem hook executed")

    def __iter__(self):  # pragma: no cover - must not be called
        raise AssertionError("caller-owned iter hook executed")

    def __len__(self):  # pragma: no cover - must not be called
        raise AssertionError("caller-owned len hook executed")


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_stage2016_projection_modules_do_not_use_fstrings_for_publication_paths() -> None:
    offenders: list[str] = []
    for path in sorted(PROJECTION_ROOT.glob("*.py")):
        tree = ast.parse(_source(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert offenders == []


def test_stage2016_repaired_final_json_update_boundary_is_explicit() -> None:
    for relative in (
        "error_fields.py",
        "success_fields.py",
    ):
        source = _source(FINALIZATION_ROOT / relative)
        assert "compact.update(safe_model_evidence_final_json_fields(record))" not in source
        assert "model_evidence_fields = safe_model_evidence_final_json_fields(record)" in source
        assert "compact.update(model_evidence_fields)" in source


def test_stage2016_safe_mapping_preserves_dict_subclass_without_calling_hooks() -> None:
    hostile = HostileDict({"probability": 0.5})
    assert safe_mapping_keys(hostile) == (("probability",), "")
    assert safe_mapping_get(hostile, "probability") == 0.5
    assert mapping_readable(hostile) is True
    materialized = json_value(hostile)
    assert materialized["probability"] == 0.5


def test_stage2016_safe_mapping_rejects_generic_mapping_without_calling_hooks() -> None:
    hostile = HostileMapping()
    assert safe_mapping_keys(hostile) == ((), "unreadable_model_evidence_mapping")
    assert safe_mapping_get(hostile, "probability", replacement="missing") == "missing"
    assert mapping_readable(hostile) is False
    materialized = json_value(hostile)
    assert materialized["unavailable_reason"] == "unreadable_model_evidence_mapping"
    assert materialized["value_type"] == "HostileMapping"


def test_stage2016_unsupported_text_objects_are_evidence_not_hooks() -> None:
    hostile = HostileText()
    assert safe_str(hostile) == "<HostileText>"
    value = json_value({"bad": hostile})
    assert value["bad"]["unavailable_reason"] == "unsupported_model_evidence_text"
    assert value["bad"]["value_type"] == "HostileText"


def test_stage2016_publication_projects_model_evidence_without_hook_materialization() -> None:
    record = {
        "file": "stage2016.exe",
        "path": "stage2016.exe",
        "classification": "suspicious",
        "score": 0.7,
        "tags": ["stage2016_publication"],
        "feature_probabilities": {
            "markov": 0.5,
            "markov_unavailable_reason": HostileText(),
        },
        "model_evidence": {
            "feature_probabilities": {
                "graph": 0.25,
                HostileText(): 0.1,
            }
        },
    }
    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"]["markov"] == 0.5
    assert evidence["unavailable_reasons"]["feature_probabilities.markov_unavailable_reason"] == "non_text_model_unavailable_reason"
    failures = evidence["model_failures"]
    assert any(failure["failure_type"] == "invalid_existing_feature_probability_field" for failure in failures)


def test_stage2016_build_model_evidence_rejects_unreadable_mapping_evidence() -> None:
    projected = build_model_evidence_final_json_fields({"model_evidence": HostileMapping()})
    evidence = projected["model_evidence"]
    assert evidence["unavailable_reasons"]["model_evidence"] == "unreadable_model_evidence_record"
    assert evidence["model_failures"][0]["failure_type"] == "invalid_model_evidence_record"
