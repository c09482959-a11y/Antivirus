import os

import pytest

from Virus_Scan.contracts.env_config import bool_env, env_contains_text, float_env, int_env_status, str_env
from Virus_Scan.contracts.runtime_contracts import RuntimeContractRegistry, RuntimeContractViolation, _contract_json_safe
from Virus_Scan.contracts.schema_registry import get_schema, register_schema
from Virus_Scan.contracts.work_stage import capacity_for_stage, stage_code, stage_name_from_code


class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("do not call format")


class HostileNumeric:
    touched = 0

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not call int")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not call float")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")


class HostileMapping:
    touched = 0

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not call items")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not call get")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not call iter")

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("do not call getitem")


class HostileIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not call iter")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")


def reset_hostiles():
    HostileText.touched = 0
    HostileNumeric.touched = 0
    HostileMapping.touched = 0
    HostileIterable.touched = 0


def test_env_config_rejects_hostile_reader_values_without_hooks():
    reset_hostiles()
    assert int_env_status("ANY", 7, 1, 9, env_reader=lambda name, default: HostileNumeric()) == ("parse_error", 7)
    old_value = os.environ.get("UMIGE_STAGE1554_BOOL")
    os.environ["UMIGE_STAGE1554_BOOL"] = "false"
    try:
        assert bool_env("UMIGE_STAGE1554_BOOL", True) is False
    finally:
        if old_value is None:
            os.environ.pop("UMIGE_STAGE1554_BOOL", None)
        else:
            os.environ["UMIGE_STAGE1554_BOOL"] = old_value
    assert str_env("UMIGE_STAGE1554_MISSING", HostileText()) == ""
    assert env_contains_text(HostileText()) is False
    assert HostileText.touched == 0
    assert HostileNumeric.touched == 0


def test_work_stage_rejects_hostile_stage_and_code_without_hooks():
    reset_hostiles()
    assert capacity_for_stage(HostileText()).name == "generic"
    assert stage_code(HostileText()) == 60
    assert stage_name_from_code(HostileNumeric()) == "scan"
    assert HostileText.touched == 0
    assert HostileNumeric.touched == 0


def test_runtime_contracts_reject_unknown_mappings_and_materialize_without_hooks():
    reset_hostiles()
    reg = RuntimeContractRegistry()
    with pytest.raises(RuntimeContractViolation):
        reg.register_queue(HostileMapping())
    assert HostileMapping.touched == 0

    safe = _contract_json_safe({"bad_text": HostileText(), "bad_iter": HostileIterable()})
    assert safe["bad_text"]["unavailable_reason"].startswith("non_materializable_runtime_contract")
    assert safe["bad_iter"]["unavailable_reason"].startswith("non_materializable_runtime_contract")
    assert HostileText.touched == 0
    assert HostileIterable.touched == 0


def test_runtime_contract_error_paths_do_not_format_hostile_inputs():
    reset_hostiles()
    reg = RuntimeContractRegistry()
    reg.register_queue({"queue_id": "q", "owner_domain": "scheduler"})
    with pytest.raises(RuntimeContractViolation):
        reg.require_owner(HostileText(), "scheduler")
    with pytest.raises(RuntimeContractViolation):
        reg.require_owner("q", HostileText())
    assert HostileText.touched == 0


def test_schema_registry_rejects_hostile_names_versions_without_hooks():
    reset_hostiles()
    assert get_schema(HostileText()) is None
    with pytest.raises(KeyError):
        register_schema(HostileText(), owner="contracts.result_record", version=1)
    with pytest.raises(RuntimeError):
        register_schema("result_record", owner=HostileText(), version=1)
    with pytest.raises(RuntimeError):
        register_schema("result_record", owner="contracts.result_record", version=HostileNumeric())
    assert HostileText.touched == 0
    assert HostileNumeric.touched == 0

from Virus_Scan.contracts.file_fingerprint import FileFingerprintSnapshot, source_fingerprint_snapshot
from Virus_Scan.contracts.game_engine_threats import (
    GameThreatAccumulator,
    contains_any_term,
    engine_from_path,
    has_malwarebazaar_metadata_marker,
    malwarebazaar_metadata_sections,
    matches_regex,
    strip_negated_behavior_phrases,
)
from Virus_Scan.contracts.unity_behavior import detect_unity_runtime_behavior


class HostilePathLike:
    touched = 0

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not call fspath")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")


def test_file_fingerprint_rejects_hostile_pathlike_without_hooks(tmp_path):
    HostilePathLike.touched = 0
    snap = source_fingerprint_snapshot(HostilePathLike())
    assert snap.as_dict() == {"path": "", "size": 0, "mtime": 0, "sha256": ""}
    direct = FileFingerprintSnapshot(path=HostilePathLike(), size=HostileNumeric(), mtime=HostileNumeric(), sha256=HostileText())
    assert direct.path == ""
    assert direct.size == 0
    assert direct.mtime == 0
    assert direct.sha256 == ""
    assert HostilePathLike.touched == 0
    assert HostileNumeric.touched == 0
    assert HostileText.touched == 0


def test_game_engine_threat_helpers_reject_hostile_text_without_hooks():
    reset_hostiles()
    assert engine_from_path(HostileText()) == "unknown"
    assert contains_any_term(HostileText(), ("x",)) is False
    assert matches_regex(HostileText(), "x") is False
    assert matches_regex("text", HostileText()) is False
    assert strip_negated_behavior_phrases(HostileText()) == ""
    assert has_malwarebazaar_metadata_marker(HostileText()) is False
    assert malwarebazaar_metadata_sections(HostileText(), HostileNumeric()) == ""
    acc = GameThreatAccumulator()
    acc.add("fam", "reason", "tag")
    assert acc.to_record(engine=HostileText(), source=HostileText())["engine"] == ""
    assert HostileText.touched == 0
    assert HostileNumeric.touched == 0


def test_unity_behavior_rejects_hostile_text_without_hooks():
    reset_hostiles()
    assert detect_unity_runtime_behavior(HostileText()) == ()
    assert HostileText.touched == 0
    assert "unity_lifecycle" in detect_unity_runtime_behavior("void Awake() { Process.Start(); }")
    assert "process_exec" in detect_unity_runtime_behavior("void Awake() { Process.Start(); }")
