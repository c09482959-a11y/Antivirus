from Virus_Scan.scanners.binary_appended_payload import scan_appended_payload
from Virus_Scan.scanners.image_malformed import fast_image_sample_malformed_status
from Virus_Scan.scanners import ilspy

import ast
from pathlib import Path


def _caught_default_findings(root: Path):
    findings = []

    class Visitor(ast.NodeVisitor):
        def __init__(self, path):
            self.path = path
            self.stack = []

        def visit_FunctionDef(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        def visit_AsyncFunctionDef(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        def visit_Try(self, node):
            for handler in node.handlers:
                for sub in ast.walk(handler):
                    if isinstance(sub, ast.Return):
                        value = sub.value
                        kind = None
                        if value is None:
                            kind = "return_none"
                        elif isinstance(value, (ast.List, ast.Dict, ast.Tuple, ast.Set)) and len(getattr(value, "elts", getattr(value, "keys", []))) == 0:
                            kind = "return_empty_literal"
                        elif isinstance(value, ast.Constant) and value.value in (None, False, 0, 0.0, ""):
                            kind = f"return_falsey_{value.value!r}"
                        if kind:
                            findings.append((self.path.as_posix(), sub.lineno, self.stack[-1] if self.stack else "<module>", kind))
                    if isinstance(sub, ast.Assign):
                        value = sub.value
                        kind = None
                        if isinstance(value, (ast.List, ast.Dict, ast.Tuple, ast.Set)) and len(getattr(value, "elts", getattr(value, "keys", []))) == 0:
                            kind = "assign_empty_literal"
                        elif isinstance(value, ast.Constant) and value.value in (None, False, 0, 0.0, ""):
                            kind = f"assign_falsey_{value.value!r}"
                        if kind:
                            findings.append((self.path.as_posix(), sub.lineno, self.stack[-1] if self.stack else "<module>", kind))
            self.generic_visit(node)

    for path in sorted((root / "Virus_Scan" / "scanners").rglob("*.py")):
        if "/ci/" in path.as_posix():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        Visitor(path.relative_to(root)).visit(tree)
    return findings


def test_phase3_caught_exception_default_gate_is_clean():
    findings = _caught_default_findings(Path.cwd())
    assert findings == []


def test_appended_payload_scan_failure_emits_scanner_evidence():

    class BrokenPayload:
        def __bool__(self):
            return True

        def startswith(self, *_args, **_kwargs):
            raise ValueError("broken appended payload probe")

    tags = []
    suspicious = scan_appended_payload(BrokenPayload(), tags)
    assert suspicious is False
    assert "scanner_failure_evidence_recorded" in tags
    assert "scanner_failure_evidence:binary:appended_payload_scan" in tags


def test_fast_image_sample_probe_failure_fails_closed_to_malformed():

    class BrokenSample:
        def __bool__(self):
            return True

        def __bytes__(self):
            raise ValueError("broken image sample")

    assert fast_image_sample_malformed_status("broken.png", BrokenSample()) == "probe_error"


def test_ilspy_engine_context_failure_is_explicit():

    def boom(*_args, **_kwargs):
        raise RuntimeError("engine context failed")

    should, ctx = ilspy.unity_ilspy_should_run(
        "sample.dll",
        tags=["unity"],
        strings_blob="BSJB",
        read_bytes=lambda *_args, **_kwargs: b"BSJB dotnet metadata",
        metadata_detector=lambda _blob: True,
        engine_context_inferer=boom,
    )
    assert should is False
    assert ctx["is_dotnet"] is True
    assert ctx["reason"] == "ilspy_disabled"
    failure_evidence = ctx["scanner_failure_evidence"]
    assert isinstance(failure_evidence, dict)
    assert failure_evidence["scanner_name"] == "ilspy"
    assert failure_evidence["scanner_stage"] == "engine_context"
    scan_integrity = ctx["scan_integrity"]
    assert isinstance(scan_integrity, dict)
    assert scan_integrity["final_json_must_record"] is True
