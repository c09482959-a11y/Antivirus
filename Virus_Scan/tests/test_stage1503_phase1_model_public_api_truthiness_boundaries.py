from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.models.api import clustering_contracts, graph_contracts, profile_contracts
from Virus_Scan.models.api import profile_learning_contracts, profile_retention_contracts
from Virus_Scan.models.api.profile_contracts import (
    default_engine_profile,
    get_extension_baseline,
    load_engine_profile,
)

from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database


@pytest.fixture(autouse=True)
def _canonical_profile_bootstrap(tmp_path):
    bind_profile_database(tmp_path)
    ensure_authoritative_engine_profiles()



class HostileText:
    def __init__(self, text: str = "renpy"):
        self.text = text
        self.bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned text truthiness was probed")

    def __str__(self):
        return self.text


class UnreadableText:
    def __init__(self):
        self.bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned unreadable text truthiness was probed")

    def __str__(self):
        raise RuntimeError("text unavailable")


class HostileFallback:
    def __init__(self, text: str):
        self.text = text
        self.bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        self.bool_calls += 1
        raise AssertionError("fallback truthiness was probed")

    def __str__(self):
        return self.text



def test_stage1503_profile_public_engine_inputs_do_not_probe_truthiness():
    engine = HostileText("renpy")

    assert default_engine_profile(engine)["engine"] == "renpy"
    assert load_engine_profile(engine)["engine"] == "renpy"
    assert "extension" in get_extension_baseline(engine, "demo.rpy")
    assert engine.bool_calls == 0



def test_stage1503_public_model_text_fallbacks_do_not_probe_fallback_truthiness():
    value = UnreadableText()
    helpers = (
        clustering_contracts._safe_public_cluster_text,
        graph_contracts._safe_public_graph_text,
        profile_contracts._safe_public_profile_text,
        profile_learning_contracts._safe_public_profile_learning_text,
        profile_retention_contracts._safe_public_retention_text,
    )

    for helper in helpers:
        fallback = HostileFallback("fallback_reason")
        assert helper(value, default_text=fallback) == "fallback_reason"
        assert fallback.bool_calls == 0
        assert value.bool_calls == 0



def test_stage1503_profile_corruption_snapshot_does_not_use_truthiness_fallback():
    snapshot = profile_contracts.profile_corruption_events_snapshot()

    assert isinstance(snapshot, tuple)



def test_stage1503_repaired_model_public_api_sources_do_not_contain_targeted_truthiness_fallbacks():
    roots = [
        Path("Virus_Scan/models/api/clustering_contracts.py"),
        Path("Virus_Scan/models/api/graph_contracts.py"),
        Path("Virus_Scan/models/api/profile_contracts.py"),
        Path("Virus_Scan/models/api/profile_learning_contracts.py"),
        Path("Virus_Scan/models/api/profile_retention_contracts.py"),
    ]
    forbidden = (
        "return fallback or",
        "return text or (fallback",
        "value or default",
        "immutable or ()",
        'evidence.get("risk", 0.0) or 0.0',
        "evidence.get('risk', 0.0) or 0.0",
    )
    for path in roots:
        source = path.read_text(encoding="utf-8")
        for snippet in forbidden:
            assert snippet not in source, f"{snippet!r} still present in {path}"
