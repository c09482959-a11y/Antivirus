from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.models.graph.common import (
    graph_first_reason,
    normalize_graph_tags_with_reason,
    safe_graph_metadata_value,
    safe_graph_sequence,
)


class HostileGraphText:
    touched = 0

    def __str__(self):  # pragma: no cover - failure proves caller-owned text hook ran
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ executed")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __format__ executed")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ executed")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __iter__ executed")


class HostileMetadata(dict):
    touched = 0

    def get(self, key, default=None):  # pragma: no cover - dict.get descriptor must be used
        type(self).touched += 1
        raise AssertionError("caller-owned mapping get executed")


def test_stage2003_graph_sequence_and_normalizers_keep_reasoned_no_hook_boundary() -> None:
    HostileGraphText.touched = 0
    value = HostileGraphText()

    sequence, reason = safe_graph_sequence(("alpha", value), "graph_sequence_unavailable")
    tags, tag_reason = normalize_graph_tags_with_reason(("alpha", value), "graph_tags_unavailable")

    assert sequence[0] == "alpha"
    assert sequence[1].startswith("unsupported_graph_text_type:")
    assert reason == "graph_sequence_unavailable"
    assert "detection_stage_degraded" in tags
    assert tag_reason == "graph_tags_unavailable"
    assert HostileGraphText.touched == 0


def test_stage2003_graph_first_reason_and_metadata_use_internal_reasoned_text() -> None:
    HostileGraphText.touched = 0
    value = HostileGraphText()
    metadata = {"engine_hint": value}

    reason = graph_first_reason(None, " graph degraded ", value)
    metadata_value, metadata_reason = safe_graph_metadata_value(metadata, "engine_hint")

    assert reason == "graph degraded"
    assert metadata_value == ""
    assert metadata_reason == "unreadable_graph_metadata_value"
    assert HostileGraphText.touched == 0


def test_stage2003_graph_common_source_removed_direct_public_helper_recursion_sites() -> None:
    source = read_python_file(Path("Virus_Scan/models/graph/common.py"))

    forbidden = (
        "text, item_reason = safe_graph_text_with_reason(item, reason)",
        "values, values_reason = safe_graph_sequence(value, reason)",
        "text = str.strip(safe_graph_text(value))",
        "return str.strip(safe_graph_text(default)) if default is not None else ''",
        "text, reason = safe_graph_text_with_reason(value, 'unreadable_graph_metadata_value')",
    )
    for snippet in forbidden:
        assert snippet not in source
