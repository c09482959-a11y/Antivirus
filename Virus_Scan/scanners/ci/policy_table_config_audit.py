"""Scanner Phase 7 policy-table ownership audit.

This audit is intentionally scanner-owned and static: it inspects actual scanner
Python source and reports uppercase policy-like module assignments that are not
backed by immutable scanner config snapshots, public manifests, exception
contracts, or clearly bounded implementation constants.
"""
from __future__ import annotations

from dataclasses import dataclass
import ast
from pathlib import Path
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_ast_field_status


@dataclass(frozen=True, slots=True)
class PolicyTableFinding:
    path: str
    line: int
    name: str
    reason: str


_CONFIG_SNAPSHOT_NAMES = frozenset({
    "_PAYLOAD_POLICY",
    "_PICKLE_POLICY",
    "_RAW_CHUNK_POLICY",
    "_TEXT_POLICY",
    "_FILETYPE_POLICY",
    "_ENGINE_POLICY",
    "_BINARY_POLICY",
    "_ARCHIVE_POLICY",
    "_SCANNER_LIMITS_POLICY",
})

_ALLOWED_ASSIGNMENT_NAMES = frozenset({
    "__all__",
    "USE_ILSPY",  # read-only public alias backed by EnginePolicySnapshot
    "DECODE_LAYER_DEBUG",  # static debug flag; not a mutable behavioral table
    "CONTEXTUAL_BASELINE_VERSION",
    "CONTEXT_AMPLIFIER_VERSION",
})

_ALLOWED_CONFIG_PATH_PREFIXES = (
    "_CONFIG_ROOT",
    "_DEFAULT_",
)

_ALLOWED_PUBLIC_MANIFEST_FILES = frozenset({
    Path("Virus_Scan/scanners/api/public_contracts.py"),
})

_ALLOWED_CI_MANIFEST_DIR = Path("Virus_Scan/scanners/ci")


def _ast_line(node: ast.AST) -> int:
    value, reason = no_hook_ast_field_status(node, (type(node),), "lineno")
    if reason:
        return 1
    return value if type(value) is int and type(value) is not bool else 1


def _rel_path_text(path: Path) -> str:
    return Path.as_posix(path)


def _parse_failure_reason(exc: BaseException) -> str:
    return "parse_failed:" + type(exc).__name__


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Return explicit AST parent ownership without mutating AST nodes."""
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def _is_module_assignment(node: ast.AST, parents: Mapping[ast.AST, ast.AST]) -> bool:
    return isinstance(parents.get(node), ast.Module)


def _assigned_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Assign):
        return tuple(target.id for target in node.targets if isinstance(target, ast.Name))
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return (node.target.id,)
    return ()


def _assignment_value(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Assign):
        return node.value
    if isinstance(node, ast.AnnAssign):
        return node.value
    return None


def _is_config_snapshot_assignment(name: str, value: ast.AST | None) -> bool:
    if name in _CONFIG_SNAPSHOT_NAMES:
        return isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id.startswith("load_") and value.func.id.endswith("_snapshot")
    return False


def _is_config_snapshot_alias(value: ast.AST | None) -> bool:
    if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
        return value.value.id in _CONFIG_SNAPSHOT_NAMES
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in {"frozenset", "tuple", "MappingProxyType"}:
        # Public read-only aliases may wrap an immutable snapshot property.
        args = value.args or []
        return bool(args) and _is_config_snapshot_alias(args[0])
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "dict":
        args = value.args or []
        return bool(args) and _is_config_snapshot_alias(args[0])
    return False


def _is_regex_implementation(name: str, value: ast.AST | None) -> bool:
    if not name.endswith("_RE") and name != "API_REGEX":
        return False
    return isinstance(value, ast.Call)


def _is_exception_contract(name: str, value: ast.AST | None) -> bool:
    return name.endswith("_EXCEPTIONS") and isinstance(value, ast.Tuple)


def _is_public_or_ci_manifest(path: Path) -> bool:
    if path in _ALLOWED_PUBLIC_MANIFEST_FILES:
        return True
    try:
        return path.is_relative_to(_ALLOWED_CI_MANIFEST_DIR)
    except AttributeError:
        return str(path).startswith(str(_ALLOWED_CI_MANIFEST_DIR) + "/")


def _literal_collection_size(value: ast.AST | None) -> int:
    if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
        return len(value.elts)
    if isinstance(value, ast.Dict):
        return len(value.keys)
    return 0


def scan_policy_table_config_findings(root: str | Path = "Virus_Scan/scanners") -> tuple[PolicyTableFinding, ...]:
    root_path = Path(root)
    findings: list[PolicyTableFinding] = []
    for path in sorted(root_path.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeError) as exc:
            findings.append(PolicyTableFinding(_rel_path_text(rel), 1, "<parse>", _parse_failure_reason(exc)))
            continue
        parents = _parent_map(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not _is_module_assignment(node, parents):
                continue
            value = _assignment_value(node)
            for name in _assigned_names(node):
                if not name.isupper() and not name.startswith("_"):
                    continue
                if any(name.startswith(prefix) for prefix in _ALLOWED_CONFIG_PATH_PREFIXES):
                    continue
                if name in _ALLOWED_ASSIGNMENT_NAMES or name.startswith("_PICKLE_PROTOCOL_"):
                    continue
                if _is_public_or_ci_manifest(rel):
                    continue
                if _is_exception_contract(name, value):
                    continue
                if _is_config_snapshot_assignment(name, value):
                    continue
                if _is_config_snapshot_alias(value):
                    continue
                if _is_regex_implementation(name, value):
                    continue
                if _literal_collection_size(value) > 0:
                    findings.append(PolicyTableFinding(_rel_path_text(rel), _ast_line(node), name, "literal_policy_table_not_config_backed"))
                elif isinstance(value, ast.BoolOp) or (isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "get_init_value"):
                    findings.append(PolicyTableFinding(_rel_path_text(rel), _ast_line(node), name, "hidden_runtime_policy_or_state"))
    return tuple(findings)


__all__ = ("PolicyTableFinding", "scan_policy_table_config_findings")
