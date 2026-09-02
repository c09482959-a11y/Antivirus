"""Phase 6 payload decoding authority audit.

This gate verifies scanner-owned payload decoding remains canonical.  Domain
code may identify candidate byte windows, but base64/hex/url/compression decode
mechanics and decoded-payload record shaping must live in the scanner-owned
``Virus_Scan.scanners.payload`` bounded modules, the canonical
``Virus_Scan.scanners.payload_decode`` public API surface, or public scanner API
contracts.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import ast
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_ast_field_status

_CANONICAL_DECODER = Path("Virus_Scan/scanners/payload_decode.py")
_CANONICAL_DECODER_PACKAGE = Path("Virus_Scan/scanners/payload")
_DELETED_DUPLICATE_FILES = (
    Path("Virus_Scan/detection/evidence/pickle_payloads.py"),
    Path("Virus_Scan/detection/evidence/pickle_fragments.py"),
)
_FORBIDDEN_CALLS = frozenset({
    "base64.b64decode",
    "base64.urlsafe_b64decode",
    "binascii.unhexlify",
    "urllib.parse.unquote_to_bytes",
    "zlib.decompress",
    "gzip.decompress",
    "bz2.decompress",
    "lzma.decompress",
})
_FORBIDDEN_IMPORT_MODULES = frozenset({
    "Virus_Scan.detection.evidence.pickle_payloads",
    "Virus_Scan.detection.evidence.pickle_fragments",
    "Virus_Scan.detection.evidence.payload_decode",
})


@dataclass(frozen=True, slots=True)
class PayloadAuthorityFinding:
    path: str
    line: int
    kind: str
    detail: str

    def to_record(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PayloadAuthorityAuditResult:
    findings: tuple[PayloadAuthorityFinding, ...]
    scanned_files: int
    deleted_duplicate_files_absent: bool

    @property
    def ok(self) -> bool:
        return not self.findings and self.deleted_duplicate_files_absent

    def to_record(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "scanned_files": self.scanned_files,
            "deleted_duplicate_files_absent": self.deleted_duplicate_files_absent,
            "findings": [finding.to_record() for finding in self.findings],
        }


def _ast_line(node: ast.AST) -> int:
    value, reason = no_hook_ast_field_status(node, (type(node),), "lineno")
    if reason:
        return 0
    return value if type(value) is int and type(value) is not bool else 0


def _ast_text(value: object) -> str:
    return value if type(value) is str else ""


def _rel_path_text(path: Path) -> str:
    return Path.as_posix(path)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return _ast_text(node.id)
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        attr = _ast_text(node.attr)
        if base and attr:
            return base + "." + attr
        return attr
    return ""


def _is_python_source(path: Path, base: Path) -> bool:
    if not path.is_relative_to(base):
        return False
    rel = path.relative_to(base)
    if path.suffix != ".py":
        return False
    if "__pycache__" in rel.parts or "tests" in rel.parts:
        return False
    if not rel.parts or rel.parts[0] != "Virus_Scan":
        return False
    return not (len(rel.parts) >= 2 and rel.parts[1] not in {"scanners", "detection"})


def _parent_map(tree: ast.AST) -> dict[int, ast.AST]:
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    return parents


def _enclosing_function(parents: dict[int, ast.AST], target: ast.AST) -> str:
    node: ast.AST | None = target
    while node is not None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
        node = parents.get(id(node))
    return ""


def _allowed_decode_call(rel: Path, call_name: str, function_name: str) -> bool:
    if rel == _CANONICAL_DECODER or _CANONICAL_DECODER_PACKAGE in (rel, *rel.parents):
        return True
    return rel == Path("Virus_Scan/scanners/pickle_scan.py") and function_name in {"_safe_load_rpa_index", "_iter_renpy_rpa_members"} and call_name == "zlib.decompress"

def audit_payload_authority(root: str | Path = ".") -> PayloadAuthorityAuditResult:
    base = Path(root)
    findings: list[PayloadAuthorityFinding] = []
    scanned = 0
    for duplicate in _DELETED_DUPLICATE_FILES:
        if (base / duplicate).exists():
            findings.append(PayloadAuthorityFinding(_rel_path_text(duplicate), 0, "duplicate_file_present", "duplicate detection payload decoder file remains"))
    for path in sorted((base / "Virus_Scan").rglob("*.py")):
        if not _is_python_source(path, base):
            continue
        scanned += 1
        rel = path.relative_to(base)
        source = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=Path.as_posix(path))
        parents = _parent_map(tree)
        for node in ast.walk(tree):
            rel_text = _rel_path_text(rel)
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module in _FORBIDDEN_IMPORT_MODULES:
                    findings.extend(
                        (
                            PayloadAuthorityFinding(
                                rel_text,
                                _ast_line(node),
                                "forbidden_payload_import",
                                _ast_text(node.module),
                            ),
                        )
                    )
            elif isinstance(node, ast.Import):
                findings.extend(
                    PayloadAuthorityFinding(
                        rel_text,
                        _ast_line(node),
                        "forbidden_payload_import",
                        _ast_text(alias.name),
                    )
                    for alias in node.names
                    if alias.name in _FORBIDDEN_IMPORT_MODULES
                )
            elif isinstance(node, ast.Call):
                name = _call_name(node.func)
                function_name = _enclosing_function(parents, node)
                if name in _FORBIDDEN_CALLS and not _allowed_decode_call(rel, name, function_name):
                    findings.extend(
                        (
                            PayloadAuthorityFinding(
                                rel_text,
                                _ast_line(node),
                                "duplicate_decode_call",
                                name,
                            ),
                        )
                    )
    return PayloadAuthorityAuditResult(
        tuple(findings),
        scanned,
        all(not (base / duplicate).exists() for duplicate in _DELETED_DUPLICATE_FILES),
    )


__all__ = ("PayloadAuthorityAuditResult", "PayloadAuthorityFinding", "audit_payload_authority")
