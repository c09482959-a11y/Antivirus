"""Stage2021 routing context no-hook boundary regressions."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from Virus_Scan.routing import (
    context_container_fingerprints,
    context_reporting_tags,
    context_router_identity,
    engine_detect,
    engine_target_detection,
    extension_fileio,
    extension_intrastage,
    extensions,
    magic_extension_tags,
    magic_header_rules,
)
from Virus_Scan.routing.extension_outcome import RouteScanOutcome
from Virus_Scan.routing.context_identity_types import EngineContextIdentity
from Virus_Scan.routing.engine_fingerprints import EngineFingerprint


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

    def __hash__(self):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("hash hook executed")

    def __eq__(self, _other):  # pragma: no cover - test fails if reached
        type(self).touched += 1
        raise AssertionError("eq hook executed")


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


def _valid_engine_context_identity(**overrides: object) -> EngineContextIdentity:
    data = {
        "container_engine": "renpy",
        "container_engine_confidence": 0.9,
        "artifact_engine": "renpy",
        "artifact_engine_confidence": 0.8,
        "declared_extension": ".rpy",
        "sniffed_type": "renpy_source",
        "sniffed_embedded_types": (),
        "extension_mismatch": False,
        "cross_engine_artifact": False,
        "engine_mismatch": False,
        "effective_analysis_engine": "renpy_source",
        "baseline_key": "renpy:.rpy",
        "extension_baseline": ".rpy",
        "contextual_baseline": "renpy",
        "container_extension_baseline": "renpy:.rpy",
        "secondary_baseline_keys": (),
        "baseline_lookup_order": ("renpy:.rpy",),
        "learning_baseline_key": None,
        "blocked_baseline_keys": (),
        "learning_allowed": False,
        "learning_reason": "trusted",
        "fingerprint_evidence": (),
    }
    data.update(overrides)
    return EngineContextIdentity(**data)


def test_stage2021_reporting_tags_reject_hostile_fields_without_hooks() -> None:
    _HostileValue.reset()
    hostile = _HostileValue()

    tags = context_reporting_tags.routing_identity_reporting_tags(
        {
            "container_engine": hostile,
            "artifact_engine": hostile,
            "sniffed_type": hostile,
            "declared_extension": hostile,
            "effective_analysis_engine": hostile,
            "cross_engine_artifact": hostile,
            "engine_mismatch": hostile,
            "extension_mismatch": hostile,
            "sniffed_embedded_types": hostile,
        }
    )

    assert tags == []
    assert _HostileValue.touched == 0


def test_stage2021_reporting_tags_preserve_exact_primitive_context_tags() -> None:
    tags = context_reporting_tags.routing_identity_reporting_tags(
        {
            "container_engine": "renpy",
            "artifact_engine": "unity",
            "sniffed_type": "pe",
            "declared_extension": ".png",
            "effective_analysis_engine": "embedded_pe_payload",
            "cross_engine_artifact": True,
            "engine_mismatch": True,
            "extension_mismatch": True,
            "sniffed_embedded_types": ("pe",),
        }
    )

    assert "cross_engine_renpy_contains_unity" in tags
    assert "declared_png_sniffs_as_pe" in tags
    assert "embedded_pe_payload" in tags


def test_stage2021_router_identity_rejects_hostile_values_without_hooks() -> None:
    _HostileValue.reset()
    hostile = _HostileValue()

    identity = context_router_identity.file_identity_from_router_identity(
        {"ext": hostile, "tags": (hostile,), "magic_type": hostile, "magic_stage": hostile, "extension_mismatch": hostile}
    )

    assert identity is not None
    assert identity.declared_extension == ""
    assert identity.sniffed_type == "unknown"
    assert identity.evidence == ("extension:none",)
    assert _HostileValue.touched == 0


def test_stage2021_router_identity_rejects_hostile_mapping_without_hooks() -> None:
    _HostileMapping.reset()

    assert context_router_identity.file_identity_from_router_identity(_HostileMapping()) is None
    assert _HostileMapping.touched == 0


def test_stage2021_container_fingerprint_does_not_rescan_parent_after_no_selection(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")
    calls: list[Path] = []
    original_fingerprint = context_container_fingerprints.fingerprint_container
    original_select = context_container_fingerprints._select_local_container

    def _fake_fingerprint(root: Path) -> EngineFingerprint:
        calls.append(root)
        return EngineFingerprint("other", 0.1, 0.1, ("weak_test_fingerprint",))

    def _fake_select(_scored):
        return None

    try:
        context_container_fingerprints.fingerprint_container = _fake_fingerprint
        context_container_fingerprints._select_local_container = _fake_select
        fingerprint = context_container_fingerprints.container_fingerprint(None, sample)
    finally:
        context_container_fingerprints.fingerprint_container = original_fingerprint
        context_container_fingerprints._select_local_container = original_select

    assert fingerprint.engine == "other"
    assert fingerprint.evidence == ("container_root_unavailable",)
    assert calls == [tmp_path]


def test_stage2022_context_identity_validate_rejects_hostile_fields_without_hooks() -> None:
    _HostileValue.reset()
    hostile = _HostileValue()

    with pytest.raises(ValueError):
        _valid_engine_context_identity(container_engine=hostile).validate(context=hostile)
    with pytest.raises(ValueError):
        _valid_engine_context_identity(sniffed_embedded_types=(hostile,)).validate(context="routing_context")
    with pytest.raises(ValueError):
        _valid_engine_context_identity(engine_mismatch=hostile).validate(context="routing_context")

    assert _HostileValue.touched == 0


def test_stage2022_engine_detect_rejects_hostile_inputs_without_hooks() -> None:
    _HostileValue.reset()
    _HostileMapping.reset()
    hostile = _HostileValue()

    assert engine_detect._cluster_engine_prefix(_HostileMapping(), hostile) == "unknown_noext_cluster_"
    assert engine_detect.select_active_profile_engine(_HostileMapping(), threshold=hostile) == "other"
    assert engine_detect._engine_read_prefix(hostile, max_bytes=hostile) == b""

    report = engine_detect.engine_confidence_report(
        _HostileMapping(),
        path=hostile,
        tags=hostile,
        strings_blob=hostile,
    )
    inferred = engine_detect.infer_engine_context(
        hostile,
        file_structure=hostile,
        strings_blob=hostile,
    )

    assert report["active_profile"] == "other"
    assert report["raw_context"] == {}
    assert inferred["unknown"] > 0.0
    assert _HostileValue.touched == 0
    assert _HostileMapping.touched == 0


def test_stage2022_routing_helpers_reject_hostile_inputs_without_hooks() -> None:
    _HostileValue.reset()
    _HostileMapping.reset()
    hostile = _HostileValue()

    assert extension_fileio.stage_decode_latin1(hostile) == ""
    assert extension_intrastage.run_raw_task_queue(hostile) == []
    assert magic_header_rules.is_valid_renpy_bytecode_header(hostile, hostile) is False
    assert magic_header_rules.renpy_bytecode_identity_tags(hostile)[-1] == "renpy_bytecode_unknown"
    assert extensions._image_is_jpeg(hostile, path=hostile) is False
    assert extensions._is_rpa_path(hostile) is False
    assert extensions._raw_stage_cache_allowed(_HostileMapping()) is False

    outcome = RouteScanOutcome(tags=(hostile, "safe_tag"), suspicious=hostile, identity=_HostileMapping())
    assert outcome.tags == ("safe_tag",)
    assert outcome.suspicious is False
    assert outcome.identity == {}

    scores = engine_target_detection.detect_target_engine_context_from_layout(
        hostile,
        hostile,
        rel_fn=lambda _path, _root: "",
        read_prefix=lambda _path, _limit: b"",
        log_recoverable=lambda _context, _exc: None,
        clamp=lambda value, lower, upper: max(lower, min(upper, value)),
    )
    assert scores["unknown"] > 0.0

    tags: list[str] = []
    magic_extension_tags.apply_extension_consistency_tags(tags, hostile, hostile, rpgm_recovered=False)
    magic_extension_tags.apply_magic_mismatch_tags(tags, hostile, hostile, mismatch=True, rpgm_recovered=False)
    magic_extension_tags.apply_filetype_category_tags(tags, hostile, hostile, hostile, hostile)
    assert "filetype_category_input_rejected" in tags

    assert _HostileValue.touched == 0
    assert _HostileMapping.touched == 0


def test_stage2021_routing_context_sources_have_no_repaired_hookable_patterns() -> None:
    modules = (context_container_fingerprints, context_reporting_tags, context_router_identity)
    forbidden_text = (
        "fallback_parent =",
        "return fingerprint_container(fallback_parent)",
        "str(router_identity.get",
        "str(record.get",
        ".as_record_fields().items()",
        "f\"cross_engine_",
        "f\"declared_",
        "f\"embedded_",
        "f\"extension:",
        "f\"magic:",
        "f\"router:",
    )
    for module in modules:
        source = Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(tree)), module.__name__
        for text in forbidden_text:
            assert text not in source, (module.__name__, text)


def test_stage2022_engine_detect_context_sources_have_no_repaired_hookable_patterns() -> None:
    modules = (
        engine_detect,
        engine_target_detection,
        extension_fileio,
        extension_intrastage,
        extensions,
        magic_extension_tags,
        magic_header_rules,
    )
    forbidden_text = (
        "dict(engine_context or {})",
        "str(strings_blob or '')",
        "str(file_structure or '')",
        "str(snapshot.scan_engine_hint or 'auto')",
        "str(cli_engine or 'auto')",
        "str(engine or 'other')",
        "str(ext or '<no_ext>')",
        "str(data or \"\")",
        "str(ext or \"\")",
        "str(path).lower().endswith",
        "int(max_files or 600)",
        "int(max_workers or stage_parallel_workers())",
        "log_error(f'",
        "return f'",
        'log_error(f"',
        'return f"',
        'raise ValueError(f"',
    )
    for module in modules:
        source = Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(tree)), module.__name__
        for text in forbidden_text:
            assert text not in source, (module.__name__, text)
