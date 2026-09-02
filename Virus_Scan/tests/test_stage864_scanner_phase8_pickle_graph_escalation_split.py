from pathlib import Path
import ast

from Virus_Scan.scanners.pickle import embedded_payloads, escalation, graph_tags
from Virus_Scan.scanners.pickle import embedded_projection, embedded_streams
from Virus_Scan.scanners.pickle import escalation_base64, escalation_context, escalation_io, escalation_rpyc
from Virus_Scan.scanners.pickle import fragment_tags, graph_base, source_opcode_exec, trigger_evidence
from Virus_Scan.scanners.ci.payload_authority_audit import audit_payload_authority
from Virus_Scan.scanners.ci.policy_table_config_audit import scan_policy_table_config_findings
from Virus_Scan.scanners.ci.suppressed_failure_audit import validate_suppressed_failure_manifest


def _function_lengths(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    lengths = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and getattr(node, "end_lineno", None):
            lengths[node.name] = node.end_lineno - node.lineno + 1
    return lengths


def test_pickle_graph_and_escalation_are_bounded_modules():
    modules = [
        graph_tags,
        graph_base,
        trigger_evidence,
        fragment_tags,
        source_opcode_exec,
        escalation,
        escalation_base64,
        escalation_context,
        escalation_io,
        escalation_rpyc,
        embedded_payloads,
        embedded_projection,
        embedded_streams,
    ]
    for module in modules:
        path = Path(module.__file__)
        assert path.read_text(encoding="utf-8").count("\n") + 1 <= 200, path
        assert all(length <= 75 for length in _function_lengths(path).values()), path


def test_pickle_public_facades_preserve_behavior(tmp_path):
    raw_pickle = b"\x80\x04cposix\nsystem\n."
    graph_result = graph_tags.pickle_opcode_graph_tags(raw_pickle, path="sample.rpyc")
    assert "pickle_opcode_graph_analyzed" in graph_result
    assert graph_tags.unify_pickle_detection_tags is graph_base.unify_pickle_detection_tags

    sample = tmp_path / "sample.rpy"
    sample.write_text("pickle.loads('gANjYnVpbHRpbnMKZXZhbAou')", encoding="utf-8")
    fast_result = escalation.pickle_fast_escalation_prefilter(sample)
    assert "pickle_deep_scan_escalated" in set(fast_result["tags"])

    embedded_result = embedded_payloads.pickle_embedded_payload_tags(raw_pickle, path="sample.rpyc")
    assert isinstance(embedded_result, list)


def test_phase8_split_audits_remain_clean():
    suppressed = validate_suppressed_failure_manifest(Path("."))
    assert suppressed["unclassified"] == []
    assert suppressed["stale_manifest"] == []
    assert suppressed["count_mismatches"] == []
    assert scan_policy_table_config_findings("Virus_Scan/scanners") == ()
    assert audit_payload_authority(Path(".")).ok is True
