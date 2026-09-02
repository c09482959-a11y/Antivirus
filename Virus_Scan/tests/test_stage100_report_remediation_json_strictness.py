import json
import math
from pathlib import Path

from Virus_Scan.publication.json_writer import finalize_scan_results, load_partial_results
from Virus_Scan.runtime.determinism import make_governance_snapshot
from Virus_Scan.runtime.causal_snapshots import build_causal_snapshot
from Virus_Scan.runtime.governance_invariants import stable_digest
from Virus_Scan.yara.cache import _write_manifest_json_atomic


def test_finalizer_sanitizes_non_finite_numbers_without_emitting_nan(tmp_path):
    out = tmp_path / "scan_results.json"
    assert finalize_scan_results(str(out), {"sample.bin": {"file": "sample.bin", "score": float('nan'), "tags": ["scanner_failure"]}})
    raw = out.read_text(encoding="utf-8")
    assert "NaN" not in raw and "Infinity" not in raw
    data = json.loads(raw)
    assert data["sample.bin"]["score"]["non_finite_float"].lower() == "nan"


def test_yara_manifest_writer_sanitizes_non_finite_numbers(tmp_path):
    manifest = tmp_path / "manifest.json"
    assert _write_manifest_json_atomic(str(manifest), {"score": float('inf'), "nested": {"x": -float('inf')}})
    raw = manifest.read_text(encoding="utf-8")
    assert "Infinity" not in raw and "NaN" not in raw
    loaded = json.loads(raw)
    assert loaded["score"]["non_finite_float"].lower() == "inf"


def test_runtime_digests_sanitize_non_finite_values_deterministically():
    snap1 = make_governance_snapshot(queue_state={"bad": float('nan')})
    snap2 = make_governance_snapshot(queue_state={"bad": float('nan')})
    assert snap1.stable_digest() == snap2.stable_digest()
    assert stable_digest({"bad": float('inf')}) == stable_digest({"bad": float('inf')})


def test_causal_snapshot_sanitizes_non_finite_digest_inputs():
    event = {"seq": 1, "domain": "d", "kind": "k", "event_key": "e", "value": float('nan')}
    snap = build_causal_snapshot(events=[event], budgets={"b": float('inf')})
    as_dict = snap.as_dict()
    assert as_dict["events"][0]["value"]["unavailable_reason"] == "non_finite_causal_event_number"


def test_causal_snapshot_rejects_unknown_as_dict_event_without_calling_hook():
    class HostileAsDictEvent:
        touched = 0

        @property
        def as_dict(self):  # pragma: no cover - must not execute
            type(self).touched += 1
            raise AssertionError("caller-owned as_dict hook executed")

        @property
        def seq(self):  # pragma: no cover - must not execute
            type(self).touched += 1
            raise AssertionError("caller-owned seq property executed")

        def __iter__(self):  # pragma: no cover - must not execute
            type(self).touched += 1
            raise AssertionError("caller-owned iteration executed")

    HostileAsDictEvent.touched = 0
    snap = build_causal_snapshot(events=[HostileAsDictEvent()])
    event = snap.as_dict()["events"][0]

    assert HostileAsDictEvent.touched == 0
    assert event["event_unavailable"] is True
    assert event["event_unavailable_reason"] == "non_materializable_causal_event"
    assert event["domain"].startswith("causal_text_unavailable:")
