from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners.archives.text_boundaries import archive_exact_attr_int, archive_exact_attr_text
from Virus_Scan.scanners.ci.payload_authority_audit import _ast_line
from Virus_Scan.scanners.config.error_contracts import ScannerConfigError, ScannerConfigFailure


class _HostileMember:
    def __getattribute__(self, name: str):  # pragma: no cover - must not run
        raise AssertionError(f"hostile member hook executed for {name}")


class _HostileAst(ast.AST):
    def __getattribute__(self, name: str):  # pragma: no cover - must not run
        raise AssertionError(f"hostile AST hook executed for {name}")


class _HostileFailure:
    def __getattribute__(self, name: str):  # pragma: no cover - must not run
        raise AssertionError(f"hostile failure hook executed for {name}")


def test_stage2077_archive_exact_attr_helpers_reject_custom_getattribute_without_invocation() -> None:
    hostile = _HostileMember()

    assert archive_exact_attr_text(hostile, _HostileMember, "filename") == "unsafe_archive_member_text_attr"
    try:
        archive_exact_attr_int(hostile, _HostileMember, "file_size")
    except TypeError as exc:
        assert str(exc) == "unsafe_archive_member_numeric_attr"
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("hostile numeric archive member was accepted")


def test_stage2077_scanner_ci_ast_line_rejects_hostile_ast_without_invocation() -> None:
    assert _ast_line(_HostileAst()) == 0


def test_stage2077_scanner_config_error_uses_no_hook_failure_type_boundary() -> None:
    error = ScannerConfigError(_HostileFailure())

    assert "scanner_config invalid: unsupported_failure_type:_HostileFailure" in str(error)


def test_stage2077_scanner_branch_no_local_object_getattribute_bypasses() -> None:
    scanner_root = Path("Virus_Scan/scanners")
    offenders = []
    for path in scanner_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "object.__getattribute__" in text:
            offenders.append(path.as_posix())
    assert offenders == []


def test_stage2077_loader_failure_evidence_preserves_mapping_records() -> None:
    failure = ScannerConfigFailure(
        "archive_policy",
        "memory",
        "invalid",
        failure_evidence=({"reason": "bad", "nested": {"value": 1}},),
    )
    error = ScannerConfigError(failure)

    assert "archive_policy invalid: invalid" in str(error)
    assert failure.failure_evidence[0]["reason"] == "bad"
