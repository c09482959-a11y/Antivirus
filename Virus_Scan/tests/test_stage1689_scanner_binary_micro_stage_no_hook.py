from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scanners.binary_micro_stage import micro_stage_collect


class HostileMicroStageValue:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not fspath")

    def __eq__(self, other):
        type(self).touched += 1
        raise RuntimeError("do not compare")


def test_stage1689_micro_stage_rejects_hostile_kind_without_comparison_or_text_hooks() -> None:
    HostileMicroStageValue.touched = 0

    tags = micro_stage_collect(HostileMicroStageValue(), "powershell")

    assert HostileMicroStageValue.touched == 0
    assert "scanner_failure_evidence_recorded" in tags
    assert "binary_final_json_must_record" in tags
    assert "unsafe_micro_stage_kind_rejected" in tags
    assert "scanner_failure_evidence:binary:micro_stage_unsupported" in tags


def test_stage1689_file_identity_rejects_hostile_path_without_fspath_or_string_hooks() -> None:
    HostileMicroStageValue.touched = 0

    tags = micro_stage_collect("file_identity", HostileMicroStageValue())

    assert HostileMicroStageValue.touched == 0
    assert "scanner_failure_evidence_recorded" in tags
    assert "binary_final_json_must_record" in tags
    assert "unsafe_micro_stage_payload_path_rejected" in tags
    assert "scanner_failure_evidence:binary:micro_stage_file_identity" in tags


def test_stage1689_runtime_context_rejects_hostile_payload_without_truthiness_or_text_hooks() -> None:
    HostileMicroStageValue.touched = 0

    tags = micro_stage_collect("runtime_context", HostileMicroStageValue())

    assert HostileMicroStageValue.touched == 0
    assert "scanner_failure_evidence_recorded" in tags
    assert "binary_final_json_must_record" in tags
    assert "unsafe_micro_stage_payload_text_rejected" in tags
    assert "scanner_failure_evidence:binary:micro_stage_runtime_context" in tags


def test_stage1689_micro_stage_preserves_existing_binary_identity_and_context_behavior(tmp_path: Path) -> None:
    sample = tmp_path / "payload.exe"
    sample.write_bytes(b"MZ" + b"powershell CreateRemoteThread VirtualAlloc WriteProcessMemory" + b"\x00" * 32)

    identity_tags = set(micro_stage_collect("file_identity", sample))
    context_tags = set(micro_stage_collect("binary_context", sample))
    pe_api_tags = set(micro_stage_collect("pe_api", sample))

    assert {"pe_file", "pe_exe", "executable_file"}.issubset(identity_tags)
    assert "powershell_exec" in context_tags
    assert "process_injection" in pe_api_tags


def test_stage1689_micro_stage_source_has_no_payload_truthy_stringification_boundary() -> None:
    source = read_python_file(Path("Virus_Scan/scanners/binary_micro_stage.py"))

    forbidden = (
        "Path(str(payload))",
        "str(payload)",
        "str(\"\" if payload is None else payload)",
        "\"\" if payload is None else str(payload)",
        "if kind ==",
        "elif kind ==",
        "kind in {",
    )
    for pattern in forbidden:
        assert pattern not in source
