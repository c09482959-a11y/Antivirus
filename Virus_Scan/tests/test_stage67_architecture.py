from __future__ import annotations

import ast
import hashlib
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_RUNTIME_IMPORTS = (
    'Virus_Scan.cli','Virus_Scan.scanners','Virus_Scan.scheduler','Virus_Scan.reporting',
    'Virus_Scan.yara','Virus_Scan.models','Virus_Scan.orchestration',
)


def _module_name(path: Path) -> str:
    return '.'.join(path.with_suffix('').relative_to(ROOT.parent).parts)


@lru_cache(maxsize=1)
def _parsed_module_sources():
    modules = {
        _module_name(p): p
        for p in ROOT.rglob('*.py')
        if '__pycache__' not in p.parts and 'tests' not in p.parts
    }
    parsed = {}
    for mod, path in modules.items():
        parsed[mod] = (path, ast.parse(path.read_text(encoding='utf-8')))
    return parsed


def _internal_import_graph():
    parsed = _parsed_module_sources()
    graph = {m: set() for m in parsed}
    for mod, (path, tree) in parsed.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                target = node.module or ''
                if target in parsed:
                    graph[mod].add(target)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in parsed:
                        graph[mod].add(alias.name)
    return graph


def _cycles(graph):
    out = []
    temp, perm, stack = set(), set(), []
    def dfs(node):
        temp.add(node); stack.append(node)
        for nxt in graph.get(node, ()): 
            if nxt in temp:
                out.append(stack[stack.index(nxt):] + [nxt])
            elif nxt not in perm:
                dfs(nxt)
        stack.pop(); temp.remove(node); perm.add(node)
    for node in graph:
        if node not in perm:
            dfs(node)
    return out


def test_stage67_internal_import_graph_is_acyclic():
    assert _cycles(_internal_import_graph()) == []


def test_stage67_yara_phase_ownership_is_acyclic():
    graph = _internal_import_graph()
    yara_edges = {
        src: sorted(dst for dst in dsts if dst.startswith('Virus_Scan.yara.'))
        for src, dsts in graph.items() if src.startswith('Virus_Scan.yara.')
    }
    forbidden = []
    for src, dsts in yara_edges.items():
        if src.endswith('.loader'):
            forbidden.extend((src, dst) for dst in dsts if dst.endswith(('.match', '.scoring')))
        if src.endswith('.match'):
            forbidden.extend((src, dst) for dst in dsts if dst.endswith(('.loader', '.scoring')))
        if src.endswith('.scoring'):
            forbidden.extend((src, dst) for dst in dsts if dst.endswith(('.loader', '.match')))
    assert forbidden == []


def test_stage67_runtime_layer_stays_platform_only():
    bad = []
    for path in (ROOT / 'runtime').glob('*.py'):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(FORBIDDEN_RUNTIME_IMPORTS):
                        bad.append((path.name, alias.name))
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ''
                if mod.startswith(FORBIDDEN_RUNTIME_IMPORTS):
                    bad.append((path.name, mod))
    assert bad == []


def test_stage67_cross_layer_duplicate_policy_helpers_stay_zero():
    layers = {'core','routing','scheduler','runtime','yara','scanners','models','reporting','cli','contracts','utils','detection'}
    policy_names = {
        '_write_yara_manifest','_yara_source_fingerprint','_umige_stage_code','_umige_stage_name_from_code',
        'normalize_scan_path','scan_path_text','_umige_result_is_passive_fast_asset_result',
        '_int_env','ordered_unique_tags','_umige_const_eval_string_node',
        'get_scan_extension','_tag_validation_text','assign_cluster_with_context','_cluster_now','_umige_queue_now',
    }
    by_hash = {}
    for _mod, (path, tree) in _parsed_module_sources().items():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name not in policy_names:
                continue
            body = ast.dump(ast.Module(body=node.body, type_ignores=[]), include_attributes=False)
            by_hash.setdefault(hashlib.sha256(body.encode()).hexdigest(), []).append((path, node.name, node.lineno))
    bad = []
    for items in by_hash.values():
        if len(items) < 2:
            continue
        item_layers = {p.relative_to(ROOT).parts[0] for p, _, _ in items if p.relative_to(ROOT).parts[0] in layers}
        if len(item_layers) > 1:
            bad.append([(str(p.relative_to(ROOT)), n, line) for p, n, line in items])
    assert bad == []


def test_stage1659_test_suite_has_no_global_attribute_patch_registry() -> None:
    """Prevent reintroducing test-wide patch registries outside lexical scopes."""
    offenders = []
    tests_root = ROOT / "tests"
    forbidden_file_names = {"_" + "patch" + "_helpers.py"}
    forbidden_snippets = (
        "patches." + "set_attr(",
        "_" + "patch" + "_helpers",
        "_" + "PATCHERS",
        "stop_" + "all()",
    )
    for path in sorted(tests_root.rglob("*.py")):
        rel = path.relative_to(ROOT)
        if path.name in forbidden_file_names:
            offenders.append((str(rel), 0, "global_patch_helper_module"))
            continue
        text = path.read_text(encoding="utf-8")
        for snippet in forbidden_snippets:
            if snippet in text:
                offenders.append((str(rel), 0, snippet))
    assert offenders == []


def teardown_module() -> None:
    """Release repository-wide parsed AST cache before pytest process shutdown."""
    _parsed_module_sources.cache_clear()
