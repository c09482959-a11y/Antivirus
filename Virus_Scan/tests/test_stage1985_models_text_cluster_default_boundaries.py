"""Stage1985 model text and clustering default-boundary regressions."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.models.behavior_sequence_contract import _model_sequence_detached_text
from Virus_Scan.models.clustering.common import cluster_first_reason, safe_cluster_text
from Virus_Scan.models.clustering.risk import _cluster_member_last_seen


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.bool_calls = 0
        obj.strip_calls = 0
        return obj

    def __bool__(self):  # pragma: no cover - failure proves unsafe truthiness
        self.bool_calls += 1
        raise AssertionError("caller-owned truthiness was invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves unsafe strip
        self.strip_calls += 1
        raise AssertionError("caller-owned strip was invoked")


class HostileScalar:
    def __str__(self):  # pragma: no cover - failure proves unsafe string conversion
        raise AssertionError("caller-owned __str__ was invoked")

    def __bool__(self):  # pragma: no cover - failure proves unsafe truthiness
        raise AssertionError("caller-owned __bool__ was invoked")


class ClusterRecord:
    def __init__(self, metadata):
        self.available = True
        self.present = True
        self.corrupt = False
        self.metadata = metadata


def _source(relative: str) -> str:
    return Path(relative).read_text(encoding="utf-8")


def test_stage1985_behavior_sequence_uses_default_text_without_caller_hooks() -> None:
    value = HostileText(" behavior_tag ")
    default_text = HostileText(" default_tag ")
    blank = HostileText("   ")

    assert _model_sequence_detached_text(value, default_text=default_text) == "behavior_tag"
    assert _model_sequence_detached_text(blank, default_text=default_text) == " default_tag "
    assert _model_sequence_detached_text(HostileScalar(), default_text=default_text) == " default_tag "
    assert value.bool_calls == 0
    assert value.strip_calls == 0
    assert default_text.bool_calls == 0
    assert default_text.strip_calls == 0
    assert blank.bool_calls == 0
    assert blank.strip_calls == 0


def test_stage1985_clustering_text_defaults_without_fallback_keyword_route() -> None:
    value = HostileText(" unity ")
    default_text = HostileText(" unknown ")

    assert safe_cluster_text(value, default_text=default_text) == "unity"
    assert safe_cluster_text(HostileScalar(), default_text=default_text) == " unknown "
    assert cluster_first_reason(None, HostileScalar(), default_text=default_text) == "unknown"
    assert value.bool_calls == 0
    assert value.strip_calls == 0
    assert default_text.bool_calls == 0
    assert default_text.strip_calls == 0


def test_stage1985_cluster_member_last_seen_uses_named_default_metric() -> None:
    assert _cluster_member_last_seen(ClusterRecord({"last_seen": 4.5}), 1.0) == 4.5
    assert _cluster_member_last_seen(ClusterRecord({}), 1.0) == 1.0


def test_stage1985_repaired_sources_do_not_restore_fallback_keyword_routes() -> None:
    behavior_source = _source("Virus_Scan/models/behavior_sequence_contract.py")
    cluster_common_source = _source("Virus_Scan/models/clustering/common.py")
    cluster_risk_source = _source("Virus_Scan/models/clustering/risk.py")

    assert "fallback" not in behavior_source
    assert "fallback" not in cluster_common_source
    assert "fallback" not in cluster_risk_source
    assert "safe_cluster_text(value, *, fallback" not in cluster_common_source
    assert "cluster_first_reason(*values, fallback" not in cluster_common_source
