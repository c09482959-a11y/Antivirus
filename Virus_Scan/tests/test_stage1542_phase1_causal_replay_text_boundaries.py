from __future__ import annotations

from Virus_Scan.runtime.causal_event_stream import EventBus, ReplayTombstone
from Virus_Scan.runtime.causal_snapshots import build_causal_snapshot, CausalReplaySnapshot


class HostileText:
    def __str__(self):  # pragma: no cover - failure path must not be called
        raise AssertionError("raw __str__ was invoked")

    def __bool__(self):  # pragma: no cover - failure path must not be called
        raise AssertionError("truthiness was invoked")


class HostilePath(HostileText):
    touched = 0

    def __fspath__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise AssertionError("caller-owned __fspath__ was invoked")


class EventObj:
    seq = 3
    domain = HostileText()
    kind = HostileText()
    event_key = HostileText()
    schema_version = 1
    owner = "runtime"
    parent_seq = None


def test_stage1542_causal_snapshot_never_raw_stringifies_hostile_mapping_or_event_fields():
    hostile_key = HostileText()
    hostile_value = HostileText()
    snap = build_causal_snapshot(
        events=[EventObj()],
        budgets={hostile_key: {"value": hostile_value}},
        dependencies={HostilePath(): "ok"},
        invariants={"seen": {hostile_value}},
        domain_generations={hostile_key: 1},
        generation=7,
    )

    materialized = snap.as_dict()
    assert materialized["generation"] == 7
    assert materialized["events"][0]["domain"].startswith("causal_text_unavailable:")
    assert materialized["events"][0]["kind"].startswith("causal_text_unavailable:")
    assert any(key.startswith("causal_text_unavailable:") for key in materialized["budgets"])
    assert any(key.startswith("causal_text_unavailable:") for key in materialized["dependencies"])
    assert HostilePath.touched == 0
    assert any(item.startswith("causal_text_unavailable:") for item in materialized["invariants"]["seen"])


def test_stage1542_event_bus_payload_and_compressed_replay_use_detached_causal_text():
    bus = EventBus()
    event = bus.emit(
        "runtime",
        "unit",
        {HostileText(): HostileText(), "path": HostilePath(), "stable": "value"},
        workload_id=HostileText(),
        lineage_id=HostileText(),
    )

    row = event.as_dict()
    assert row["lineage_id"].startswith("causal_text_unavailable:")
    assert row["workload_id"].startswith("causal_text_unavailable:")
    assert any(key.startswith("causal_text_unavailable:") for key in row["payload"])
    assert any(value.startswith("causal_text_unavailable:") for value in row["payload"].values())
    assert row["payload"]["path"].startswith("causal_text_unavailable:")
    assert HostilePath.touched == 0

    compressed = bus.compressed_replay()[0]
    assert any(key.startswith("causal_text_unavailable:") for key in compressed["payload_keys"])
    assert "path" in compressed["payload_keys"]
    assert bus.replay_digest() == bus.replay_digest()


def test_stage1542_replay_tombstone_and_checkpoint_restore_do_not_raw_stringify_hostile_fields():
    tombstone = ReplayTombstone(
        seq=1,
        lineage_id=HostileText(),
        domain=HostileText(),
        kind=HostileText(),
        reason=HostileText(),
        workload_id=HostileText(),
    )
    row = tombstone.as_dict()
    assert row["lineage_id"].startswith("causal_text_unavailable:")
    assert row["domain"].startswith("causal_text_unavailable:")
    assert row["reason"].startswith("causal_text_unavailable:")

    bus = EventBus()
    checkpoint = {
        "events": (
            {
                "seq": 1,
                "lineage_id": HostileText(),
                "domain": HostileText(),
                "kind": HostileText(),
                "workload_id": HostileText(),
                "event_key": HostileText(),
                "severity": HostileText(),
                "owner": HostileText(),
                "propagation": HostileText(),
                "causal_digest": HostileText(),
                "payload": {HostileText(): HostileText()},
            },
        )
    }
    bus.restore_checkpoint(checkpoint)
    restored = bus.canonical_replay()[0]
    assert restored["lineage_id"].startswith("causal_text_unavailable:")
    assert restored["domain"].startswith("causal_text_unavailable:")
    assert any(key.startswith("causal_text_unavailable:") for key in restored["payload"])
