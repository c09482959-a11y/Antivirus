from Virus_Scan.tests.support.static_inventory import parse_python_file

import ast
from pathlib import Path



CONTRACT_SNIPPETS_REMOVED = (
    ("Virus_Scan/contracts/path_identity.py", (
        "return ''",
        "return True",
    )),
    ("Virus_Scan/contracts/probabilistic_evidence.py", (
        "for group, values in grouped.items():",
        "for group in groups.values():",
        '(_safe_clamp(_detail_get(group, "correlated_fused", 0.0)) for group in groups.values()),',
        'invalid_inputs = sum(int.__int__(_detail_get(group, "invalid_numeric_inputs", 0) or 0) for group in groups.values()',
        'valid_inputs = sum(int.__int__(_detail_get(group, "valid_count", 0) or 0) for group in groups.values()',
        'degraded_groups = any(_detail_get(group, "degraded", False) is True for group in groups.values())',
    )),
    ("Virus_Scan/contracts/scan_evidence_cache_publication.py", (
        'key_text = f"{key_text}#{index}"',
        "objects are not coerced with ``str()`` or ``os.fspath()`` because those may",
    )),
    ("Virus_Scan/contracts/tag_evidence.py", (
        'def safe_tag_evidence_text(value: object, default: str = "") -> str:',
        "fallback, fallback_reason = no_hook_text(",
        'return "" if fallback_reason else fallback',
        "return safe_tag_evidence_text(value, default).strip()",
        "return safe_tag_evidence_text(blob).lower()",
        'return ""',
    )),
    ("Virus_Scan/contracts/telemetry.py", (
        "fallback, fallback_reason = no_hook_text(",
        'return "" if fallback_reason else str.strip(fallback)',
        'key_text = f"telemetry_context_key_{index}"',
        'key_text = f"{key_text}#{index}"',
        "return None",
    )),
    ("Virus_Scan/contracts/unity_behavior.py", (
        'if f"void {hook}" in value or f"{hook}(" in value:',
        "for needle, tag in UNITY_RUNTIME_CHECKS.items():",
    )),
    ("Virus_Scan/contracts/work_stage.py", (
        "reverse = {v: k for k, v in STAGE_CODES.items()}",
        "return reverse.get(target, f'stage_{target}')",
    )),
    ("Virus_Scan/contracts/worker_record.py", (
        'key_text = f"worker_output_json_key_{index}"',
        'key_text = f"{key_text}#{index}"',
        "fallback, fallback_reason = no_hook_text(",
        'return "" if fallback_reason else str.strip(fallback)',
        "return False",
    )),
    ("Virus_Scan/contracts/yara_hits.py", (
        "return None",
        'def _yara_text(value: Any, *, fallback: str = "") -> str:',
        "return fallback",
        "return tuple(dict.values(yara_hits))",
    )),
)


def test_stage2023_contract_open_cluster_backlog_snippets_removed() -> None:
    for filename, snippets in CONTRACT_SNIPPETS_REMOVED:
        source = Path(filename).read_text(encoding="utf-8")
        for snippet in snippets:
            assert snippet not in source


def test_stage2023_worker_record_is_shape_only_and_has_no_persistence_owner() -> None:
    tree = parse_python_file(Path("Virus_Scan/contracts/worker_record.py"))
    target_names = {
        "_best_effort_close_fd",
        "_best_effort_unlink",
        "_worker_path_text",
        "write_required_worker_output",
        "write_worker_output_fast",
        "write_worker_output_payload",
    }
    function_names = {
        node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
    }
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_modules.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    exports = next(
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets)
    )

    assert target_names.isdisjoint(function_names)
    assert not any(
        module.startswith(("Virus_Scan.runtime", "Virus_Scan.scheduler"))
        for module in imported_modules
    )
    assert {"json", "os", "pathlib", "tempfile"}.isdisjoint(imported_modules)
    assert exports == ("FailureRecord", "make_json_safe")
