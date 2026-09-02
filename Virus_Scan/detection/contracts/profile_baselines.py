"""Detection-owned profile baseline normalization helpers."""

from __future__ import annotations

from typing import MutableMapping


def ensure_extension_model_fields(baseline: MutableMapping[str, object]) -> MutableMapping[str, object]:
    baseline.setdefault("behavior_buckets", {})
    baseline.setdefault("tag_evidence", {})
    baseline.setdefault("vector_baseline", {"count": 0, "mean": [], "m2": [], "variance": [], "feature_names": []})
    timeline = baseline.setdefault("timeline_baseline", {})
    timeline.setdefault("sample_count", 0)
    timeline.setdefault("event_counts", {})
    timeline.setdefault("transition_counts", {})
    timeline.setdefault("behavior_counts", {})
    timeline.setdefault("behavior_transition_counts", {})
    timeline.setdefault("max_sequence_len", 0)
    timeline.setdefault("last_updated", None)
    baseline.setdefault("learning_gate", {"accepted": 0, "rejected": 0, "last_rejection_reason": ""})
    baseline.setdefault("tags", {})
    return baseline


__all__ = ("ensure_extension_model_fields",)
