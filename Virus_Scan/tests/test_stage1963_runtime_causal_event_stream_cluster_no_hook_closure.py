
"""Stage1963 causal event stream cluster no-hook closure regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

import pytest

from Virus_Scan.runtime.causal_event_stream import (
    CausalEvent,
    EventBus,
    ReplayTombstone,
    WorkloadEventBudget,
    _stable_payload_key,
)


class Stage1963HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("text str hook executed")

    def __repr__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("text repr hook executed")

    def __format__(self, spec):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("text format hook executed")

    def __bool__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("text bool hook executed")


class Stage1963HostileMapping(dict):
    touched = 0

    def items(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("mapping items hook executed")

    def keys(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("mapping keys hook executed")

    def __iter__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("mapping iter hook executed")

    def __bool__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("mapping bool hook executed")

    def __str__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("mapping str hook executed")

    def __repr__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("mapping repr hook executed")


class Stage1963HostileInt:
    touched = 0

    def __int__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("int hook executed")

    def __bool__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("int bool hook executed")

    def __str__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("int str hook executed")

    def __repr__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("int repr hook executed")


def _reset() -> None:
    Stage1963HostileText.touched = 0
    Stage1963HostileMapping.touched = 0
    Stage1963HostileInt.touched = 0


def test_stage1963_causal_event_stream_source_closes_current_cluster_routes() -> None:
    source = read_python_file(Path("Virus_Scan/runtime/causal_event_stream.py"))

    forbidden = (
        'return f"causal_text_unavailable:{no_hook_type_name(value)}"',
        'out[f"invalid_payload_key_{index}"]',
        'key = f"{key}#{duplicate}"',
        'missing_reason=f"{field_name}_missing"',
        'unsupported_reason=f"{field_name}_rejected"',
        'field_name=f"causal_event_{field_name}"',
        'field_name=f"causal_event_causal_path_{index}"',
        'field_name=f"replay_tombstone_{field_name}"',
        'field_name=f"workload_event_budget_{field_name}"',
        'for key, raw_count in dict.items(counter):',
        'f"workload event budget {counter_name} key rejected"',
        'field_name=f"workload_event_budget_{counter_name}_count"',
        'dict(sorted(self.reasons.items()))',
        'dict(sorted(self.per_key.items()',
        'f"non_materializable_causal_mapping:{no_hook_type_name(payload)}"',
        'k = f"{k}#{dup}"',
        'parts.append(f"{k}=<invalid_key:{reason}>")',
        'parts.append(f"{k}={causal_scalar_token(v)}")',
        'parts.append(f"{k}=({',
        'parts.append(f"{k}=<{no_hook_type_name(v)}>")',
        'f"{parent_digest}|{seq}|{domain}|{kind}|{event_key}"',
        'int(generation or 0)',
        'f"{normalized.domain}:{normalized.kind}:"',
        'f"v{contract.version}:{payload_key}"',
        'f"umige:{workload_text}:{domain_text}:{kind_text}:{self._seq + 1}"',
        '{k: v for k, v in ev.as_dict().items() if k != "timestamp"}',
        'for k in ev.payload.keys()',
        'int(ev.causal_depth or 0)',
        'int(ev.suppressed_count or 0)',
        'f"{parent.domain}->{ev.domain}"',
        'sum(domain_edges.values())',
        'sorted(lineage.items()',
        'sorted(domain_edges.items()',
        'default=causal_text, allow_nan=False).encode("utf-8", "replace")).hexdigest()',
        'float(ev.cost or 0.0)',
        'sum(self._children.values())',
    )
    assert not [pattern for pattern in forbidden if pattern in source]


def test_stage1963_causal_event_and_tombstone_field_names_reject_hooks() -> None:
    _reset()
    hostile = Stage1963HostileText()

    event = CausalEvent(
        Stage1963HostileInt(),
        hostile,
        hostile,
        hostile,
        {hostile: hostile},
        generation=Stage1963HostileInt(),
        causal_path=(Stage1963HostileInt(),),
    )
    row = event.as_dict()
    tombstone = ReplayTombstone(Stage1963HostileInt(), hostile, hostile, hostile, hostile)
    tombstone_row = tombstone.as_dict()

    assert row["domain"].startswith("causal_text_unavailable:")
    assert any(key.startswith("causal_text_unavailable:") for key in row["payload"])
    assert tombstone_row["domain"].startswith("causal_text_unavailable:")
    assert Stage1963HostileText.touched == 0
    assert Stage1963HostileInt.touched == 0


def test_stage1963_budget_and_stable_payload_key_are_owned_materialization_paths() -> None:
    _reset()
    hostile = Stage1963HostileText()
    hostile_mapping = Stage1963HostileMapping({"safe": "value"})

    budget = WorkloadEventBudget(per_key={"b": 2, "a": 3}, reasons={"z": 1})
    snapshot = budget.snapshot()
    digest = _stable_payload_key({hostile: ("x", 1), "mapping": hostile_mapping})

    assert snapshot["reasons"] == {"z": 1}
    assert list(snapshot["hot_keys"]) == ["a", "b"]
    assert len(digest) == 16
    assert Stage1963HostileText.touched == 0
    assert Stage1963HostileMapping.touched == 0


def test_stage1963_event_bus_event_key_digest_and_lineage_seed_reject_hooks() -> None:
    _reset()
    hostile = Stage1963HostileText()
    bus = EventBus()

    first = bus.emit("runtime", "exports_registered", {"count": 1}, workload_id=hostile)
    suppressed = bus.emit(
        "runtime",
        "exports_registered",
        {"count": 1},
        parent_seq=9999,
        generation=Stage1963HostileInt(),
    )

    assert first.event_key.startswith("runtime:exports_registered:")
    assert first.causal_digest
    assert suppressed.as_dict()["payload"]["suppressed"] is True
    assert bus.canonical_replay()[0]["domain"] == "runtime"
    assert "count" in bus.compressed_replay()[0]["payload_keys"]
    trace = bus.compressed_causal_trace(max_events=8, checkpoint_stride=1)
    assert trace["event_count"] >= 1
    assert trace["digest"]
    assert bus.telemetry_resource_budget()["replay_trace_cost"] == 0.0
    checkpoint = bus.deterministic_checkpoint()
    assert checkpoint["events"]
    assert "timestamp" not in checkpoint["events"][0]
    assert Stage1963HostileText.touched == 0
    assert Stage1963HostileInt.touched == 0
