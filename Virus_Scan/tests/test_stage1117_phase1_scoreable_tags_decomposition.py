import ast
from pathlib import Path

from Virus_Scan.detection.scoring.weighting.scoreable_tags import concrete_score_count, scoreable_tag_set
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence

_SCOREABLE_TAGS_PATH = Path("Virus_Scan/detection/scoring/weighting/scoreable_tags.py")


def test_stage1117_scoreable_tag_helpers_stay_bounded_after_decomposition():
    tree = ast.parse(_SCOREABLE_TAGS_PATH.read_text(encoding="utf-8"))
    oversized = {
        node.name: node.end_lineno - node.lineno + 1
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.end_lineno - node.lineno + 1 > 40
    }

    assert oversized == {}


def test_stage1117_payload_decode_execution_derivations_are_preserved():
    scoreable = scoreable_tag_set(physical_tag_evidence((
        "payload_decode_candidate", "decoded_payload_execution_chain", "powershell_exec",
    )))

    assert scoreable == {"powershell_exec"}
    assert "payload_decode_candidate" not in scoreable
    assert "decoded_payload_execution_chain" not in scoreable


def test_stage1117_pickle_family_derivations_are_preserved():
    scoreable = scoreable_tag_set(physical_tag_evidence((
        "pickle_dangerous_global", "pickle_callable_reference",
        "pickle_reduce_opcode", "powershell_exec",
    )))

    assert scoreable == {"powershell_exec"}
    assert "pickle_opcode_execution" not in scoreable
    assert "confirmed_pickle_exec_chain" not in scoreable


def test_stage1117_scoreability_projection_never_mints_atomic_or_behavior_tags():
    script_scoreable = scoreable_tag_set(physical_tag_evidence(("powershell_exec", "cmd_exec")))
    scheduled_scoreable = scoreable_tag_set(physical_tag_evidence(("schtasks_create", "remote_scheduled_task")))
    network_scoreable = scoreable_tag_set(physical_tag_evidence(("http_upload", "collection", "credential_access")))

    assert script_scoreable == {"powershell_exec", "cmd_exec"}
    assert scheduled_scoreable == {"schtasks_create", "remote_scheduled_task"}
    assert "scheduled_task" not in scheduled_scoreable
    assert network_scoreable == {"http_upload"}
    assert "network_download" not in network_scoreable
    assert "network_exfiltration" not in network_scoreable
    assert concrete_score_count(network_scoreable) == len(scoreable_tag_set(network_scoreable))


def test_stage2023_scoreable_tags_source_removed_audited_hook_patterns():
    source = _SCOREABLE_TAGS_PATH.read_text(encoding="utf-8")

    assert "return bool(direct_exfiltration or contextual_upload)" not in source
    assert "for source_tag, derived_tags in pickle_updates.items():" not in source
