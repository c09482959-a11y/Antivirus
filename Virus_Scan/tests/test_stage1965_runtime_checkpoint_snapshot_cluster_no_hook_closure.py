
"""Stage1965 runtime checkpoint/snapshot/cluster no-hook closure regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

import pytest

from Virus_Scan.runtime.causal_event_stream import EventBus
from Virus_Scan.runtime.causal_snapshots import build_causal_snapshot
from Virus_Scan.runtime.causal_text import causal_scalar_token, causal_text
from Virus_Scan.runtime.cleanup_invariants import RuntimeCleanupSnapshot
from Virus_Scan.runtime.config import ArchiveScanLimits, RuntimeConfig, StageConcurrencyLimits
from Virus_Scan.runtime.config_state import (
    configure_deep_scan_mode,
    configure_profile_corruption_policy,
)
from Virus_Scan.runtime.cluster_state import (
    RuntimeClusterState,
    configure_runtime_cluster_state,
    runtime_cluster_state_to_json,
)


class Stage1965HostileText:
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


class Stage1965HostileNumber:
    touched = 0

    def __int__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("int hook executed")

    def __index__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("index hook executed")

    def __str__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("number str hook executed")

    def __repr__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("number repr hook executed")

    def __format__(self, spec):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("number format hook executed")

    def __bool__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("number bool hook executed")


class Stage1965HostileMapping(dict):
    touched = 0

    def items(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("mapping items hook executed")

    def get(self, key, default=None):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("mapping get hook executed")

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


def _reset() -> None:
    Stage1965HostileText.touched = 0
    Stage1965HostileNumber.touched = 0
    Stage1965HostileMapping.touched = 0


def test_stage1965_runtime_source_closes_checkpoint_snapshot_text_and_cluster_rows() -> None:
    sources = {
        "causal_event_stream.py": read_python_file(Path("Virus_Scan/runtime/causal_event_stream.py")),
        "causal_snapshots.py": read_python_file(Path("Virus_Scan/runtime/causal_snapshots.py")),
        "causal_text.py": read_python_file(Path("Virus_Scan/runtime/causal_text.py")),
        "cleanup_invariants.py": read_python_file(Path("Virus_Scan/runtime/cleanup_invariants.py")),
        "cluster_state.py": read_python_file(Path("Virus_Scan/runtime/cluster_state.py")),
        "config.py": read_python_file(Path("Virus_Scan/runtime/config.py")),
        "config_state.py": read_python_file(Path("Virus_Scan/runtime/config_state.py")),
    }
    forbidden = {
        "causal_event_stream.py": (
            'f"causal_checkpoint_event_{index}_seq"',
            'field_name=f"causal_checkpoint_event_{index}"',
            'field_name=f"causal_checkpoint_event_{index}_parent_seq"',
        ),
        "causal_snapshots.py": (
            'f"causal_text_unavailable:{no_hook_type_name(value)}"',
            "key: value for key, value in dict.items(materialized)",
            'field_name=f"causal_snapshot_event_{field_name}"',
            'field_name=f"causal_snapshot_{field_name}"',
        ),
        "causal_text.py": (
            'return f"{_UNAVAILABLE_PREFIX}:{_type_name(value)}"',
            'return f"<{_type_name(value)}>"',
        ),
        "cleanup_invariants.py": (
            'raise TypeError(f"runtime cleanup {field_name} rejected")',
        ),
        "cluster_state.py": (
            'return f"{_CLUSTER_TEXT_UNAVAILABLE}:{no_hook_type_name(value)}"',
            'reason=f"unsafe_{field_name}_rejected"',
            'non_finite_reason=f"nonfinite_{field_name}"',
            'return f"{_CLUSTER_VALUE_UNAVAILABLE}:{reason}:{no_hook_type_name(value)}"',
            "return None",
            'return tuple(dict.items(value))',
            '"reason": f"{field_name}_sequence_rejected"',
            'field_name=f"{field_name}_member"',
            'evidence[f"{field_name}_unavailable_reason"] = reason',
            'evidence[f"{field_name}_value_type"] = no_hook_type_name(raw_value)',
            'name = f"{_CLUSTER_TEXT_UNAVAILABLE}:{no_hook_type_name(key)}"',
            'out[f"{name}_unavailable_reason"] = reason',
            'out[f"{name}_value_type"] = no_hook_type_name(value)',
            "for cid, centroid in list(state.cluster_signatures.items()):",
            "for evidence_name, evidence_value in rank_evidence.items():",
        ),
        "config.py": (
            'missing_reason=f"{reason}_missing"',
            'unsupported_reason=f"{reason}_unsafe_text_rejected"',
            "for key, value in self.as_dict().items():",
            'values[f"UMIGE_STAGE_LIMIT_{key_text.upper()}"] = _env_text(value, "1")',
            '"sections": sorted(payload.keys()),',
        ),
        "config_state.py": (
            'missing_reason=f"{field_name}_missing"',
            'unsupported_reason=f"{field_name}_rejected"',
            'raise ValueError(f"{field_name} rejected")',
            "raise ValueError(f'unsupported profile corruption policy: {policy}')",
        ),
    }

    assert {
        name: [pattern for pattern in patterns if pattern in sources[name]]
        for name, patterns in forbidden.items()
        if [pattern for pattern in patterns if pattern in sources[name]]
    } == {}


def test_stage1965_checkpoint_restore_records_hostile_rows_without_hooks() -> None:
    _reset()
    hostile = Stage1965HostileText()
    hostile_number = Stage1965HostileNumber()
    bus = EventBus()

    bus.restore_checkpoint(
        {
            "events": (
                {"seq": 1, "domain": "runtime", "kind": "restored"},
                {"seq": 1, "domain": "runtime", "kind": "duplicate"},
                {
                    "seq": 2,
                    "domain": hostile,
                    "kind": hostile,
                    "parent_seq": hostile_number,
                    "payload": {hostile: hostile},
                },
                hostile,
            )
        }
    )

    replay = bus.canonical_replay()
    checkpoint = bus.deterministic_checkpoint()
    reasons = {
        item["reason"] for item in checkpoint["checkpoint_restore_evidence"]
    }

    assert len(replay) == 2
    assert replay[1]["domain"].startswith("causal_text_unavailable:")
    assert "causal_checkpoint_duplicate_sequence" in reasons
    assert "causal_checkpoint_event_3_mapping_rejected" in reasons
    assert Stage1965HostileText.touched == 0
    assert Stage1965HostileNumber.touched == 0


def test_stage1965_snapshot_text_cleanup_and_cluster_paths_reject_hooks() -> None:
    _reset()
    hostile = Stage1965HostileText()
    hostile_number = Stage1965HostileNumber()

    snapshot = build_causal_snapshot(
        events=(
            hostile,
            {
                "seq": hostile_number,
                "domain": hostile,
                "kind": hostile,
                "parent_seq": hostile_number,
            },
        ),
        budgets={hostile: {"centroid_vector": (hostile_number,)}},
        generation=1,
    ).as_dict()

    assert snapshot["events"][0]["domain"].startswith("causal_text_unavailable:")
    assert snapshot["events"][1]["domain"]["unavailable_reason"] == "non_materializable_causal_event_value"
    assert snapshot["events"][1]["input_evidence"]
    assert causal_text(hostile).startswith("causal_text_unavailable:")
    assert causal_scalar_token(hostile).startswith("<Stage1965HostileText")
    with pytest.raises(TypeError, match="runtime cleanup active_thread_names rejected"):
        RuntimeCleanupSnapshot((hostile,), (), (), ())

    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    state.cluster_signatures[hostile] = (hostile_number, float("nan"), 2.0)
    state.cluster_metadata[hostile] = {
        "confidence": hostile_number,
        "malicious_ratio": "not-a-number",
        "samples": 2.5,
        "last_updated": float("inf"),
        "centroid_vector": (hostile_number, 3.0),
        hostile: hostile,
        "hostile_mapping": Stage1965HostileMapping({"safe": "value"}),
    }

    cluster_snapshot = runtime_cluster_state_to_json()
    cluster_key = next(iter(cluster_snapshot["microclusters"]))
    metadata = cluster_snapshot["microclusters"][cluster_key]

    assert cluster_key.startswith("cluster_state_text_unavailable:")
    assert "cluster_signatures" not in cluster_snapshot
    assert metadata["confidence_unavailable_reason"] == "unsafe_cluster_metadata_value_rejected"
    assert metadata["malicious_ratio_unavailable_reason"] == "unsafe_malicious_ratio_rejected"
    assert metadata["last_updated_unavailable_reason"] == "nonfinite_cluster_numeric_value"
    assert metadata["centroid_vector"] == [0.0, 3.0]
    assert any(key.startswith("cluster_state_text_unavailable:") for key in metadata)
    assert metadata["hostile_mapping"].startswith(
        "cluster_state_value_unavailable:unsafe_cluster_metadata_value_rejected"
    )
    assert metadata["hostile_mapping_unavailable_reason"] == "unsafe_cluster_metadata_value_rejected"
    assert Stage1965HostileText.touched == 0
    assert Stage1965HostileNumber.touched == 0
    assert Stage1965HostileMapping.touched == 0


def test_stage1965_runtime_config_paths_reject_hooks_and_keep_sections_deterministic() -> None:
    _reset()
    hostile = Stage1965HostileText()

    env = StageConcurrencyLimits(raw=hostile).env_mapping()
    fact = RuntimeConfig(
        archive_limits=ArchiveScanLimits(),
        stage_limits=StageConcurrencyLimits(raw=hostile),
    ).as_checkpoint_fact()

    assert env["UMIGE_STAGE_LIMIT_RAW"] == "1"
    assert fact["sections"] == ["archive_limits", "economics", "persistence", "stage_limits"]
    with pytest.raises(ValueError, match="deep_scan_mode rejected"):
        configure_deep_scan_mode(hostile)
    with pytest.raises(ValueError, match="unsupported profile corruption policy: unsupported"):
        configure_profile_corruption_policy("unsupported")
    assert Stage1965HostileText.touched == 0
