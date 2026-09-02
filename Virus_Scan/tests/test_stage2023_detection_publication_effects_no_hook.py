
"""Stage 2023 detection publication request no-hook boundaries."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.detection.publication.full_analysis_effects import (
    GraphPublicationRequest,
    LearningPublicationRequest,
    ScoredDetectionPublicationRequest,
    publish_scored_detection_state,
)


class HostileScalar:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("publication scalar __str__ must not execute")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("publication scalar __repr__ must not execute")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("publication scalar __format__ must not execute")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("publication scalar __float__ must not execute")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("publication scalar __int__ must not execute")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("publication scalar __bool__ must not execute")


class HostileIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("publication iterable must not execute")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("publication iterable length must not execute")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("publication iterable truthiness must not execute")


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, _key):
        type(self).touched += 1
        raise RuntimeError("publication mapping lookup must not execute")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("publication mapping iteration must not execute")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("publication mapping length must not execute")

    def get(self, _key, _default=None):
        type(self).touched += 1
        raise RuntimeError("publication mapping get must not execute")


def _reset() -> None:
    HostileScalar.touched = 0
    HostileIterable.touched = 0
    HostileMapping.touched = 0


def test_publication_request_builder_rejects_hostile_public_inputs_without_hooks() -> None:
    _reset()

    result = publish_scored_detection_state(
        ScoredDetectionPublicationRequest(
            path=HostileScalar(),
            node=HostileScalar(),
            tags=HostileIterable(),
            score_val=HostileScalar(),
            classification=HostileScalar(),
            active_profile=HostileScalar(),
            strings_blob=HostileScalar(),
            api_result=HostileMapping(),
            ordered_events=HostileIterable(),
            behavior_flow=HostileIterable(),
            prev_stage=HostileScalar(),
            curr_stage=HostileScalar(),
        )
    )

    assert result["graph_publication_request"] == {
        "kind": "graph_publication",
        "node": "<unknown>",
        "risk": 0.0,
        "tags": [],
    }
    learning = result["learning_publication_request"]
    assert learning["engine"] == "other"
    assert learning["path"] == ""
    assert learning["score"] == 0.0
    assert learning["classification"] == "unknown"
    assert learning["api_calls"] == []
    assert learning["ordered_event_count"] == 0
    assert learning["prev_stage"] == "unknown"
    assert learning["curr_stage"] == "unknown"
    assert HostileScalar.touched == 0
    assert HostileIterable.touched == 0
    assert HostileMapping.touched == 0


def test_publication_request_dataclasses_sanitize_direct_records_without_hooks() -> None:
    _reset()

    graph = GraphPublicationRequest(
        node=HostileScalar(),
        risk=HostileScalar(),
        tags=HostileIterable(),
    ).to_record()
    learning = LearningPublicationRequest(
        engine=HostileScalar(),
        path=HostileScalar(),
        tags=HostileIterable(),
        score=HostileScalar(),
        classification=HostileScalar(),
        api_calls=HostileIterable(),
        ordered_event_count=HostileScalar(),
        behavior_flow=HostileIterable(),
        prev_stage=HostileScalar(),
        curr_stage=HostileScalar(),
    ).to_record()

    assert graph == {
        "kind": "graph_publication",
        "node": "<unknown>",
        "risk": 0.0,
        "tags": [],
    }
    assert learning["engine"] == "other"
    assert learning["path"] == ""
    assert learning["tags"] == []
    assert learning["score"] == 0.0
    assert learning["classification"] == "unknown"
    assert learning["ordered_event_count"] == 0
    assert HostileScalar.touched == 0
    assert HostileIterable.touched == 0


def test_publication_effects_source_removes_raw_conversion_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/detection/publication/full_analysis_effects.py"))
    tree = ast.parse(source)
    forbidden = (
        '"risk": safe_clamp(self.risk),',
        '"score": safe_clamp(self.score, 0.0, 100.0),',
        "return tuple(str(v) for v in list(values or [])[:limit])",
        "score = safe_clamp(float(score_val or 0.0) / 100.0)",
        "graph_request = GraphPublicationRequest(node=str(node or path or '<unknown>'), risk=score, tags=tag_tuple)",
        "score=float(score_val or 0.0),",
        'prev_stage=str(prev_stage or "unknown"),',
        'curr_stage=str(curr_stage or "unknown"),',
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
    assert [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
