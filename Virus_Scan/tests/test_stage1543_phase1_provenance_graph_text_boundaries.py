from __future__ import annotations

from Virus_Scan.runtime.provenance_graph import ProvenanceGraphEvent, ProvenanceGraphStore


class HostileText:
    def __str__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("raw __str__ was invoked")

    def __repr__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("raw __repr__ was invoked")

    def __bool__(self):  # pragma: no cover - must not be invoked
        raise AssertionError("truthiness was invoked")


class HostilePath(HostileText):
    touched = 0

    def __fspath__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise AssertionError("caller-owned __fspath__ was invoked")


def test_stage1543_provenance_event_build_detaches_hostile_text_fields_and_payload():
    event = ProvenanceGraphEvent.build(
        event_type=HostileText(),
        subsystem=HostileText(),
        parent_ids=(HostileText(), HostilePath()),
        payload={HostileText(): HostileText(), "path": HostilePath(), "tags": {HostileText(), "stable"}},
    )

    row = event.canonical()
    assert row["event_type"].startswith("provenance_graph_text_unavailable:")
    assert row["subsystem"].startswith("provenance_graph_text_unavailable:")
    assert any(parent.startswith("provenance_graph_text_unavailable:") for parent in row["parent_ids"])
    assert not any(parent == "safe/provenance/path" for parent in row["parent_ids"])
    assert sum(parent.startswith("provenance_graph_text_unavailable:") for parent in row["parent_ids"]) >= 2
    assert any(key.startswith("provenance_graph_text_unavailable:") for key in row["payload"])
    assert any(value.startswith("provenance_graph_text_unavailable:") for value in row["payload"].values())
    assert row["payload"]["path"].startswith("provenance_graph_text_unavailable:")
    assert HostilePath.touched == 0
    assert any(item.startswith("provenance_graph_text_unavailable:") for item in row["payload"]["tags"])


def test_stage1543_provenance_store_append_mapping_and_missing_parent_are_stable_with_hostile_objects():
    store = ProvenanceGraphStore()
    store.append({
        "event_type": HostileText(),
        "origin_subsystem": HostileText(),
        "payload": {HostileText(): "ok"},
        "parent_ids": (HostileText(),),
    })

    first = store.canonical_snapshot()
    second = store.canonical_snapshot()
    assert first == second
    assert first["graph_digest"] == second["graph_digest"]
    assert first["events"][0]["event_type"].startswith("provenance_graph_text_unavailable:")
    assert first["events"][0]["subsystem"].startswith("provenance_graph_text_unavailable:")
    assert any(key.startswith("provenance_graph_text_unavailable:") for key in first["events"][0]["payload"])
    assert first["missing_parents"][0]["missing_parent"].startswith("provenance_graph_text_unavailable:")
    assert store.validate()["ok"] is False


def test_stage1543_provenance_graph_duplicate_hostile_keys_are_not_silently_overwritten():
    left = HostileText()
    right = HostileText()
    event = ProvenanceGraphEvent.build(
        event_type="dup",
        subsystem="runtime",
        payload={left: "left", right: "right"},
    )
    payload = event.canonical()["payload"]

    unavailable_keys = [key for key in payload if key.startswith("provenance_graph_text_unavailable:")]
    assert len(unavailable_keys) == 2
    assert sorted(payload.values()) == ["left", "right"]
