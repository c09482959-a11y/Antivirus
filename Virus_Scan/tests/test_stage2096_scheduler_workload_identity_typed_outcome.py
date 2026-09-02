from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.workload_identity import _sniff_workload_identity, workload_from_identity_outcome


class HostileMapping(dict):
    items_touched = 0
    get_touched = 0

    def items(self):  # pragma: no cover - failure proves unsafe hook use
        type(self).items_touched += 1
        raise AssertionError("mapping items hook executed")

    def get(self, key, default=None):  # pragma: no cover - failure proves unsafe hook use
        type(self).get_touched += 1
        raise AssertionError("mapping get hook executed")


class HostileTags:
    iter_touched = 0

    def __iter__(self):  # pragma: no cover - failure proves unsafe hook use
        type(self).iter_touched += 1
        raise AssertionError("tag iteration hook executed")


def test_stage2096_workload_identity_rejections_are_typed() -> None:
    HostileMapping.items_touched = 0
    HostileMapping.get_touched = 0
    hostile = HostileMapping(magic_stage="archive", confidence=1.0, tags=("archive_file",))

    decision = workload_from_identity_outcome(hostile)

    assert decision.accepted is False
    assert decision.workload == ""
    assert decision.reason == "workload_identity_mapping_not_owned_dict"
    assert HostileMapping.items_touched == 0
    assert HostileMapping.get_touched == 0


def test_stage2096_workload_identity_low_confidence_and_unknown_stage_are_replayable() -> None:
    low_confidence = workload_from_identity_outcome({"magic_stage": "archive", "confidence": 0.25, "tags": ("archive_file",)})
    unknown_stage = workload_from_identity_outcome({"magic_stage": "unknown", "confidence": 1.0, "tags": ()})

    assert low_confidence.accepted is False
    assert low_confidence.reason == "workload_identity_confidence_below_threshold"
    assert low_confidence.confidence == 0.25
    assert unknown_stage.accepted is False
    assert unknown_stage.reason == "unsupported_workload_identity_stage"
    assert unknown_stage.magic_stage == "unknown"


def test_stage2096_workload_identity_preserves_accepted_lanes_and_rejected_tag_reason_without_hooks() -> None:
    HostileTags.iter_touched = 0
    archive = workload_from_identity_outcome({"magic_stage": "archive", "confidence": "1.0", "tags": HostileTags()})
    binary = workload_from_identity_outcome({"magic_stage": "binary", "magic_type": "pe_mz", "confidence": 1.0})
    asset = workload_from_identity_outcome({"magic_stage": "asset", "confidence": 0.98, "tags": ("media_file",)})

    assert archive.accepted is True
    assert archive.workload == "archive"
    assert archive.tags == frozenset()
    assert binary.workload == "dotnet"
    assert asset.workload == "image"
    assert HostileTags.iter_touched == 0


def test_stage2096_sniff_identity_still_returns_replayable_unknown_evidence_for_missing_path() -> None:
    identity = _sniff_workload_identity(None)
    decision = workload_from_identity_outcome(identity)

    assert identity["magic_stage"] == "unknown"
    assert identity["magic_type"] == "unknown"
    assert identity["confidence"] == 0.0
    assert identity["path_unavailable_reason"] == "scheduler_path_missing"
    assert decision.accepted is False
    assert decision.reason == "workload_identity_confidence_below_threshold"


def test_stage2096_workload_identity_source_split_removed_tracked_default_helpers() -> None:
    root = Path(__file__).resolve().parents[1]
    identity_source = (root / "scheduler" / "queue" / "workload_identity.py").read_text(encoding="utf-8")
    outcome_source = (root / "scheduler" / "queue" / "workload_identity_outcome.py").read_text(encoding="utf-8")

    assert len(identity_source.splitlines()) < 200
    assert len(outcome_source.splitlines()) < 200
    assert "def _exact_lower_text(" not in identity_source
    assert "def _identity_items(" not in identity_source
    assert "def _identity_value(" not in identity_source
    assert "def _identity_confidence(" not in identity_source
    assert "def _identity_tags(" not in identity_source
    assert "return None" not in identity_source
    assert "Mapping[str, Any]" not in identity_source
    assert "tuple[tuple[Any, Any], ...]" not in identity_source
    assert "def _workload_from_identity(" not in outcome_source
    assert '"_workload_from_identity"' not in identity_source
    assert '"_workload_from_identity"' not in outcome_source
