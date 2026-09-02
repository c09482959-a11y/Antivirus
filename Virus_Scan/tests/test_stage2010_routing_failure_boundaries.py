"""Stage2010 routing no-hook failure-boundary regressions."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.routing import asset_triage, baseline_routing, context_container_fingerprints, engine_fingerprints


class _HostileValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("str hook executed")

    def __repr__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("format hook executed")

    def __bool__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("bool hook executed")

    def __iter__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("iter hook executed")

    def __fspath__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("fspath hook executed")


class _HostileMapping:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def items(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("items hook executed")

    def __iter__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("iter hook executed")

    def __bool__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("bool hook executed")


def test_stage2010_asset_identity_snapshot_rejects_hostile_mapping_without_hooks() -> None:
    _HostileMapping.reset()

    snapshot = asset_triage._asset_identity_snapshot(_HostileMapping())

    assert snapshot["identity_unavailable_reason"] == "asset_identity_rejected"
    assert snapshot["value_type"] == "_HostileMapping"
    assert _HostileMapping.touched == 0


def test_stage2010_unity_sample_rejects_hostile_sample_tuple_without_hooks() -> None:
    _HostileValue.reset()

    assert asset_triage._unity_sample("sample.assets", _HostileValue()) == (b"", b"", 0)
    assert _HostileValue.touched == 0


def test_stage2010_baseline_route_rejects_hostile_scalars_without_hooks() -> None:
    _HostileValue.reset()
    hostile = _HostileValue()

    route = baseline_routing.build_baseline_route(baseline_routing.BaselineRouteRequest(
        container_engine=hostile,
        artifact_engine=hostile,
        declared_extension=hostile,
        sniffed_type=hostile,
        sniffed_embedded_types=hostile,
        trusted_benign=True,
    ))

    assert route.baseline_key == "other::other::<no_ext>::unknown"
    assert route.extension_baseline == "other/<no_ext>"
    assert route.learning_allowed is True
    assert _HostileValue.touched == 0


def test_stage2010_engine_fingerprint_choose_rejects_hostile_mapping_without_hooks() -> None:
    _HostileMapping.reset()

    selected = engine_fingerprints.choose_engine(_HostileMapping())

    assert selected.engine == "other"
    assert selected.evidence == ("no_engine_fingerprint",)
    assert _HostileMapping.touched == 0


def test_stage2010_no_container_fingerprint_rejects_hostile_reason_without_hooks() -> None:
    _HostileValue.reset()

    selected = context_container_fingerprints._no_container_fingerprint(_HostileValue())

    assert selected.engine == "other"
    assert selected.evidence == ("container_context_unavailable",)
    assert _HostileValue.touched == 0


def test_stage2010_routing_sources_have_no_repaired_hookable_patterns() -> None:
    for module in (asset_triage, baseline_routing, context_container_fingerprints, engine_fingerprints):
        source = Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(tree)), module.__name__
        assert "dict(identity or {})" not in source
        assert "Path(str(file))" not in source
        assert "log_error(f" not in source
        for node in ast.walk(tree):
            guarded = {
                "_unity_sample",
                "_container_root_is_scan_safe",
            }
            if isinstance(node, ast.FunctionDef) and (module in (asset_triage, baseline_routing) or node.name in guarded):
                for handler in [child for child in ast.walk(node) if isinstance(child, ast.ExceptHandler)]:
                    assert not any(isinstance(child, ast.Return) for child in ast.walk(handler)), node.name
