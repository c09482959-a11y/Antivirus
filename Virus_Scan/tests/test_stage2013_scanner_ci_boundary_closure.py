import ast
from pathlib import Path

from Virus_Scan.scanners.ci.payload_authority_audit import _call_name, audit_payload_authority
from Virus_Scan.scanners.ci.pickle_boundary_audit import run_pickle_boundary_audit
from Virus_Scan.scanners.ci.policy_table_config_audit import scan_policy_table_config_findings
from Virus_Scan.scanners.ci.production_import_audit import audit_production_scanner_imports
from Virus_Scan.scanners.ci.public_export_smoke import discover_scanner_public_exports
from Virus_Scan.scanners.ci.public_export_smoke_cases import (
    PublicExportSmokeCaseContext,
    _mark_integrity,
    _normalize_tags,
)
from Virus_Scan.scanners.ci.suppressed_failure_audit import validate_suppressed_failure_manifest


_REPAIRED_SOURCES = (
    Path("Virus_Scan/scanners/ci/payload_authority_audit.py"),
    Path("Virus_Scan/scanners/ci/pickle_boundary_audit.py"),
    Path("Virus_Scan/scanners/ci/policy_table_config_audit.py"),
    Path("Virus_Scan/scanners/ci/production_import_audit.py"),
    Path("Virus_Scan/scanners/ci/public_export_smoke.py"),
    Path("Virus_Scan/scanners/ci/public_export_smoke_case_domains.py"),
    Path("Virus_Scan/scanners/ci/public_export_smoke_cases.py"),
    Path("Virus_Scan/scanners/ci/suppressed_failure_audit.py"),
)

_FORBIDDEN_SNIPPETS = (
    'return f"{base}.{node.attr}" if base else node.attr',
    'int(getattr(node, "lineno", 0) or 0)',
    'getattr(node, "lineno", 1)',
    'getattr(module, "__all__", ())',
    'callable(getattr(module, name, None))',
    'sorted(vars(module).items())',
    'getattr(value, "__module__", "")',
    'payload_decode.__name__',
    'raw_chunk_policy.__name__',
    'text.__name__',
    'str(self.text_path or "")',
    'dict(integrity or {})',
    'for key, site in manifest.items():',
    'lower-cased fallback view remains available',
)


class HostileText:
    def __str__(self):  # pragma: no cover - must never run
        raise AssertionError("caller text hook executed")

    def __bool__(self):  # pragma: no cover - must never run
        raise AssertionError("caller truth hook executed")

    def __iter__(self):  # pragma: no cover - must never run
        raise AssertionError("caller iteration hook executed")


class HostileTags(HostileText):
    pass


def test_stage2013_scanner_ci_sources_remove_verified_unsafe_routes() -> None:
    assert not Path("Virus_Scan/scanners/raw_chunk_policy.py").exists()
    for path in _REPAIRED_SOURCES:
        source = path.read_text(encoding="utf-8")
        for snippet in _FORBIDDEN_SNIPPETS:
            assert snippet not in source, (path, snippet)
        tree = ast.parse(source)
        assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(tree)), path


def test_stage2013_payload_call_name_uses_exact_ast_text_without_fstring() -> None:
    call = ast.parse("base64.b64decode(data)").body[0].value
    assert isinstance(call, ast.Call)
    assert _call_name(call.func) == "base64.b64decode"


def test_stage2013_public_export_case_context_rejects_hostile_text_without_hooks() -> None:
    hostile = HostileText()
    ctx = PublicExportSmokeCaseContext(
        text_path=hostile,
        binary_path=1,  # preserves existing exact primitive conversion behavior
        image_path=None,
        rpa_path=hostile,
        zip_path=hostile,
        text_blob=hostile,
        bytes_blob=bytearray(b"abc"),
        chunk_kwargs={"nested": {"items": ["a"]}},
    )
    assert ctx.text_path == "public_export_case_text_rejected:HostileText"
    assert ctx.binary_path == "1"
    assert ctx.image_path == ""
    assert ctx.bytes_blob == b"abc"
    assert ctx.chunk_kwargs["nested"]["items"] == frozenset({"a"})


def test_stage2013_public_export_case_helpers_reject_hostile_containers_without_hooks() -> None:
    assert _normalize_tags(HostileTags()) == ["tag_sequence_rejected:HostileTags"]
    marked = _mark_integrity("sample", HostileText())
    assert marked == {"integrity_rejected": "HostileText", "had_degraded_stage": True}


def test_stage2013_scanner_ci_gates_still_pass_after_no_hook_rewrite() -> None:
    assert audit_payload_authority(Path(".")).ok is True
    assert run_pickle_boundary_audit(Path(".")).ok is True
    assert scan_policy_table_config_findings("Virus_Scan/scanners") == ()
    assert audit_production_scanner_imports(Path(".")).ok is True
    assert validate_suppressed_failure_manifest(Path("."))["unclassified"] == []
    exports = discover_scanner_public_exports()
    assert exports
    assert all(type(record.module) is str and type(record.name) is str for record in exports)
