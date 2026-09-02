from __future__ import annotations

import ast
import json
from pathlib import Path

from Virus_Scan.publication.json_finalization.base_projection import (
    bounded_dict,
    bounded_list,
    canonical_chain_list,
    canonical_tag_list,
    canonical_text_list,
)
from Virus_Scan.publication.json_finalization.record_fields import (
    extension_mismatch_evidence,
    present_text,
    record_duration_seconds,
    record_extension,
    record_extension_mismatch,
)
from Virus_Scan.publication.json_finalization.scheduler_projection import timeout_evidence_projection


_BASE_PROJECTION_PATH = Path(__file__).resolve().parents[2] / "Virus_Scan/publication/json_finalization/base_projection.py"


class HostileFinalJsonValue:
    touched = 0

    @property
    def text(self):  # pragma: no cover - failure proves property probing returned
        type(self).touched += 1
        raise AssertionError("final JSON text property touched")

    @property
    def value(self):  # pragma: no cover - failure proves property probing returned
        type(self).touched += 1
        raise AssertionError("final JSON value property touched")

    def __iter__(self):  # pragma: no cover - failure proves unknown iteration returned
        type(self).touched += 1
        raise AssertionError("final JSON iteration touched")

    def __str__(self):  # pragma: no cover - failure proves string hook returned
        type(self).touched += 1
        raise AssertionError("final JSON __str__ touched")

    def __repr__(self):  # pragma: no cover - failure proves repr hook returned
        type(self).touched += 1
        raise AssertionError("final JSON __repr__ touched")


def _reset() -> None:
    HostileFinalJsonValue.touched = 0


def test_stage1579_publication_list_projection_failure_is_explicit_not_empty() -> None:
    _reset()
    projected = bounded_list(HostileFinalJsonValue())

    assert projected[0]["model_signal_projection_failed"] is True
    assert projected[0]["reason"] == "final_json_list_value_unavailable"
    assert HostileFinalJsonValue.touched == 0


def test_stage1579_publication_text_projection_failure_is_not_silently_dropped() -> None:
    _reset()
    projected = canonical_text_list(HostileFinalJsonValue())

    assert projected[0]["model_signal_projection_failed"] is True
    assert projected[0]["reason"] == "final_json_text_unavailable"
    assert HostileFinalJsonValue.touched == 0


def test_stage1579_publication_mapping_projection_failure_is_explicit_and_json_safe() -> None:
    _reset()
    projected = bounded_dict(HostileFinalJsonValue())

    assert projected["_unavailable_mapping"]["model_signal_projection_failed"] is True
    assert projected["_unavailable_mapping"]["reason"] == "final_json_mapping_projection_failure"
    assert json.dumps(projected, sort_keys=True)
    assert HostileFinalJsonValue.touched == 0


def test_stage1579_publication_tag_and_chain_projection_keep_unsupported_marker() -> None:
    _reset()
    tag_markers = canonical_tag_list(HostileFinalJsonValue())
    chain_markers = canonical_chain_list(HostileFinalJsonValue())

    assert tag_markers == ["<HostileFinalJsonValue final_json_text_unavailable>"]
    assert chain_markers == ["<HostileFinalJsonValue final_json_text_unavailable>"]
    assert HostileFinalJsonValue.touched == 0


def test_stage1579_publication_identity_numeric_and_timeout_failures_are_explicit() -> None:
    _reset()
    hostile = HostileFinalJsonValue()

    assert present_text(hostile) == "<HostileFinalJsonValue final_json_text_unavailable>"
    assert record_extension({"input_file_path": hostile}) == "final_json_extension_unavailable"
    duration = record_duration_seconds({"duration": hostile})
    timeout = timeout_evidence_projection(hostile)

    assert duration["model_signal_projection_failed"] is True
    assert duration["reason"] == "unsafe_numeric_value_rejected"
    assert timeout["scheduler_projection_failed"] is True
    assert timeout["reason"] == "unsupported_timeout_evidence"
    assert record_extension_mismatch({"tags": hostile}) is True
    assert extension_mismatch_evidence({"tags": hostile}, hostile) == [
        "extension_mismatch_tags_unavailable"
    ]
    assert json.dumps({"duration": duration, "timeout": timeout}, sort_keys=True)
    assert HostileFinalJsonValue.touched == 0


def test_stage1579_base_projection_does_not_collapse_failures_to_empty_outputs() -> None:
    tree = ast.parse(_BASE_PROJECTION_PATH.read_text(encoding="utf-8"), filename=str(_BASE_PROJECTION_PATH))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            for child in node.body:
                if isinstance(child, ast.Return) and isinstance(child.value, (ast.List, ast.Dict)):
                    if len(child.value.elts if isinstance(child.value, ast.List) else child.value.keys) == 0:
                        offenders.append(f"{_BASE_PROJECTION_PATH.name}:{child.lineno}:empty failure return")

    assert offenders == []
