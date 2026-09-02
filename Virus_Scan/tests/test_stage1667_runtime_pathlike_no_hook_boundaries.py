"""Stage 1667: runtime causal/provenance text rejects PathLike hooks."""
from __future__ import annotations

from Virus_Scan.runtime.causal_text import causal_text
from Virus_Scan.runtime.provenance_graph import ProvenanceGraphEvent


class HostilePathLike:
    touched = 0

    def __fspath__(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise RuntimeError("caller-owned __fspath__ must not execute")

    def __str__(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 100
        raise RuntimeError("caller-owned __str__ must not execute")

    def __repr__(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 100
        raise RuntimeError("caller-owned __repr__ must not execute")


class HostileMappingValue(HostilePathLike):
    pass


def test_stage1667_causal_text_rejects_pathlike_without_fspath_or_text_hooks() -> None:
    HostilePathLike.touched = 0
    text = causal_text(HostilePathLike())

    assert text.startswith("causal_text_unavailable:")
    assert HostilePathLike.touched == 0


def test_stage1667_provenance_graph_rejects_pathlike_without_fspath_or_text_hooks() -> None:
    HostilePathLike.touched = 0
    HostileMappingValue.touched = 0
    path = HostilePathLike()
    value = HostileMappingValue()

    row = ProvenanceGraphEvent.build(
        event_type="stage1667",
        subsystem="runtime",
        parent_ids=(path,),
        payload={"path": path, "value": value},
    ).canonical()

    assert row["parent_ids"][0].startswith("provenance_graph_text_unavailable:")
    assert row["payload"]["path"].startswith("provenance_graph_text_unavailable:")
    assert row["payload"]["value"].startswith("provenance_graph_text_unavailable:")
    assert HostilePathLike.touched == 0
    assert HostileMappingValue.touched == 0
