from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
import ast
from pathlib import Path

from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.detection.enrichment.strings.contextual.rpgm_js_ast import scan_rpgm_js_pseudo_ast


RPGM_JS_AST_PATH = Path("Virus_Scan/detection/enrichment/strings/contextual/rpgm_js_ast.py")


def _function_node(module, name):
    for node in ast.walk(module):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"missing function {name}")


def test_stage1494_embedded_rpgm_js_helpers_have_no_truthiness_fallbacks():
    module = ast.parse(RPGM_JS_AST_PATH.read_text())
    for name in ("_scan_embedded_string_tags", "_scan_embedded_js_model_tags"):
        node = _function_node(module, name)
        assert not any(isinstance(child, ast.BoolOp) and isinstance(child.op, ast.Or) for child in ast.walk(node))


def test_stage1494_rpgm_js_finalize_false_does_not_reintroduce_or_empty_fallback():
    module = ast.parse(RPGM_JS_AST_PATH.read_text())
    node = _function_node(module, "scan_rpgm_js_pseudo_ast")
    returns = [child for child in ast.walk(node) if isinstance(child, ast.Return)]
    assert not any(isinstance(ret.value, ast.BoolOp) and isinstance(ret.value.op, ast.Or) for ret in returns)


def test_stage1494_rpgm_js_scan_preserves_embedded_detection(tmp_path):
    js_path = tmp_path / "www" / "js" / "plugins" / "SuspiciousPlugin.js"
    js_path.parent.mkdir(parents=True)
    js_path.write_text(
        "const cp = require('child_process'); cp.exec('cmd.exe /c powershell -enc AAA'); eval(atob('QUJD'));",
        encoding="utf-8",
    )

    tags = scan_rpgm_js_pseudo_ast(js_path, finalize=False)

    assert "rpgm_plugin_js" in tags
    assert "nodejs_native_bridge" in tags
    assert "process_exec" in tags
    assert "script_execution" in tags
    assert "payload_decode_candidate" in tags
    assert "js_encoded_eval_chain" not in tags
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(tags)))
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "anchor:encoded_powershell_weak"
    )
    assert decision.status == "confirmed"
