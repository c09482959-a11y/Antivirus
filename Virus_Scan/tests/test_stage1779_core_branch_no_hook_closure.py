"""Stage1779 core branch root-cause closure regressions."""
from __future__ import annotations

from pathlib import Path
import zipfile

import pytest

from Virus_Scan.core import jsonio
from Virus_Scan.core import logging as core_logging
from Virus_Scan.runtime.api import durable_replace_regular_file
from Virus_Scan.core.cache import pre_scan_cache_lookup
from Virus_Scan.core.path_utils import ensure_parent_dir, safe_child_path
from Virus_Scan.core.paths import (
    configure_runtime_engine_and_ilspy,
    infer_behavioral_entities,
    runtime_library_score_cap,
    safe_extract_zip_member,
)
from Virus_Scan.runtime.path_runtime_state import path_runtime_owner
from Virus_Scan.tests.support.scan_cache_fixtures import disabled_scan_cache_identity
from Virus_Scan.storage import scan_cache_repository


class _HostilePath:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("do not coerce path truth")

    def __fspath__(self):
        type(self).touched += 1
        raise AssertionError("do not call caller fspath")

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("do not stringify caller path")


class _HostileArgs:
    touched = 0

    def __getattribute__(self, name):
        if name == "touched":
            return type(self).touched
        type(self).touched += 1
        raise AssertionError("do not traverse caller properties")


class _HostileNumber:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("do not coerce numeric truth")

    def __float__(self):
        type(self).touched += 1
        raise AssertionError("do not coerce float")

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("do not stringify number")


class _HostileMapping(dict):
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("do not coerce mapping truth")

    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("do not iterate caller mapping")

    def items(self):
        type(self).touched += 1
        raise AssertionError("do not call caller mapping methods")


class _HostileIterable:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("do not coerce iterable truth")

    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("do not iterate caller value")

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("do not stringify iterable")


class _HostileZipInfo(zipfile.ZipInfo):
    touched = 0

    @property
    def filename(self):
        type(self).touched += 1
        raise AssertionError("do not read hostile zip metadata")


def test_stage1779_core_path_helpers_reject_hostile_path_without_hooks(tmp_path: Path) -> None:
    hostile = _HostilePath()
    _HostilePath.touched = 0

    assert safe_child_path(tmp_path, hostile) is None
    with pytest.raises(ValueError, match="parent_path_rejected"):
        ensure_parent_dir(hostile)

    assert _HostilePath.touched == 0


def test_stage1779_pre_scan_cache_rejects_hostile_path_without_hooks() -> None:
    hostile = _HostilePath()
    _HostilePath.touched = 0

    with pytest.raises(TypeError, match="artifact_read_snapshot_required"):
        pre_scan_cache_lookup(hostile, execution_identity=disabled_scan_cache_identity())
    assert _HostilePath.touched == 0


def test_stage1779_ilspy_configuration_does_not_traverse_hostile_args() -> None:
    hostile = _HostileArgs()
    _HostileArgs.touched = 0

    configure_runtime_engine_and_ilspy(hostile)
    snapshot = path_runtime_owner().snapshot()

    assert snapshot.cli_engine_hint == "auto"
    assert snapshot.use_ilspy is False
    assert _HostileArgs.touched == 0


def test_stage1779_behavioral_entities_publish_path_rejection_without_hooks() -> None:
    hostile = _HostilePath()
    _HostilePath.touched = 0

    entities = infer_behavioral_entities(
        path=hostile,
        tags=["network_activity"],
    )

    assert entities[0]["unavailable_reason"] == "behavioral_entity_path_rejected"
    assert entities[0]["value_type"] == "_HostilePath"
    assert any(entity["entity_type"] == "network_ioc" for entity in entities)
    assert _HostilePath.touched == 0


def test_stage1779_runtime_score_rejection_is_explicit_without_hooks() -> None:
    hostile = _HostileNumber()
    _HostileNumber.touched = 0

    score, evidence = runtime_library_score_cap(hostile, tags=[])

    assert score == 0.0
    assert evidence == ["runtime_score_rejected"]
    assert _HostileNumber.touched == 0


def test_stage1779_zip_member_rejects_subclass_before_descriptor_access(tmp_path: Path) -> None:
    member = object.__new__(_HostileZipInfo)
    _HostileZipInfo.touched = 0

    with pytest.raises(ValueError, match="zip_member_metadata_rejected"):
        safe_extract_zip_member(object(), member, tmp_path)

    assert _HostileZipInfo.touched == 0


def test_stage1779_zip_member_preserves_exact_stdlib_behavior(tmp_path: Path) -> None:
    archive_path = tmp_path / "sample.zip"
    extract_root = tmp_path / "extract"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("nested/payload.txt", "ok")
    with zipfile.ZipFile(archive_path, "r") as archive:
        member = archive.infolist()[0]
        extracted = safe_extract_zip_member(archive, member, extract_root)

    assert extracted == str(extract_root / "nested" / "payload.txt")
    assert Path(extracted).read_text(encoding="utf-8") == "ok"


def test_stage1779_json_read_and_atomic_save_reject_hostile_paths_without_hooks() -> None:
    hostile = _HostilePath()
    _HostilePath.touched = 0

    read_value = jsonio.read_json_file(hostile)
    with pytest.raises(ValueError, match="explicit destination path"):
        jsonio.atomic_json_save(hostile, {"ok": True})

    assert read_value["unavailable_reason"] == "json_read_path_rejected"
    assert read_value["value_type"] == "_HostilePath"
    assert _HostilePath.touched == 0


def test_stage1779_sqlite_scan_cache_rejects_hostile_root_without_hooks() -> None:
    hostile = _HostilePath()
    _HostilePath.touched = 0

    with pytest.raises(ValueError, match="profiles_directory_required"):
        scan_cache_repository().configure(hostile, enabled=True)

    assert _HostilePath.touched == 0
    assert not hasattr(jsonio, "load_scan_cache")




def test_stage1779_json_mapping_producers_reject_hostile_mapping_without_hooks(tmp_path: Path) -> None:
    hostile = _HostileMapping(ok=True)
    _HostileMapping.touched = 0

    write_ok = jsonio._write_download_meta(tmp_path / "rules.zip", hostile)
    copied = jsonio.deepcopy_jsonable(hostile)

    assert write_ok is False
    assert copied["unavailable_reason"] == "unsupported_jsonio_value"
    assert _HostileMapping.touched == 0


def test_stage1779_dotnet_gate_rejects_hostile_evidence_without_hooks() -> None:
    hostile = _HostileMapping()
    _HostileMapping.touched = 0

    valid, reason = jsonio._dotnet_dynamic_loader_valid(hostile, {})

    assert valid is False
    assert reason == "dotnet_dynamic_loader_evidence_rejected"
    assert _HostileMapping.touched == 0


def test_stage1779_core_logging_paths_reject_hostile_values_without_hooks() -> None:
    hostile = _HostilePath()
    _HostilePath.touched = 0

    with pytest.raises(ValueError, match="core_read_path_rejected"):
        core_logging.read_file_bytes(hostile)
    with pytest.raises(TypeError, match="filesystem_durability_path_invalid"):
        durable_replace_regular_file(hostile, Path("target"))
    assert not hasattr(core_logging, "queue_atomic_replace")
    assert core_logging.queue_safe_unlink(hostile) is False
    assert core_logging.configure_single_parent_log(hostile) is None

    assert _HostilePath.touched == 0


def test_stage1779_core_scoring_rejects_hostile_numbers_without_clean_defaults() -> None:
    hostile = _HostileNumber()
    _HostileNumber.touched = 0

    with pytest.raises(ValueError, match="classification_score_rejected"):
        core_logging.classify(hostile)
    with pytest.raises(ValueError, match="calibrated_logit_rejected"):
        core_logging._calibrated_sigmoid_probability(hostile)
    with pytest.raises(ValueError, match="sigmoid_score_rejected"):
        core_logging._sigmoid_100(hostile)
    with pytest.raises(ValueError, match="sigmoid_odds_rejected"):
        core_logging.sigmoid_odds(hostile)

    assert _HostileNumber.touched == 0


def test_stage1779_stage_collector_rejects_hostile_output_without_hooks() -> None:
    hostile = _HostileIterable()
    _HostileIterable.touched = 0

    result = core_logging._safe_stage_collect("collector", lambda: hostile)

    assert result["tags"] == [
        "tag_normalization_failure_evidence",
        "detection_stage_degraded",
    ]
    assert result["suspicious"] is False
    assert _HostileIterable.touched == 0


def test_stage1779_cache_key_and_attention_reject_hostile_mappings_without_hooks() -> None:
    hostile = _HostileMapping()
    _HostileMapping.touched = 0

    key = core_logging.cache_key("core", hostile)
    with pytest.raises(ValueError, match="attention_mapping_rejected"):
        core_logging.safe_attention_lookup(hostile, "tag")

    assert key == ("core", ("cache_key_part_rejected:_HostileMapping",))
    assert _HostileMapping.touched == 0


def test_stage1779_detector_error_rejects_hostile_context_without_hooks() -> None:
    hostile = _HostileMapping()
    _HostileMapping.touched = 0

    record = core_logging.record_detector_error(
        "core",
        RuntimeError("boom"),
        context=hostile,
    )

    assert record["detector"] == "core"
    assert record["context"]["context_unavailable"]["unavailable_reason"] == "detector_context_rejected"
    assert _HostileMapping.touched == 0
