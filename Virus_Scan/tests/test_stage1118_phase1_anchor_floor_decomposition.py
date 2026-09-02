from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.escalation.anchor_floors import apply_anchor_score_floors
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_stage1118_anchor_floor_preserves_asset_entropy_cap():
    score, hits = apply_anchor_score_floors(
        80.0,
        evaluate_chain_evidence(tags=physical_tag_evidence(("high_entropy_packed",))),
        tags=physical_tag_evidence(("high_entropy_packed",)),
        stage="asset",
    )

    assert score == 18.0
    assert hits == ["asset_entropy_cap"]


def test_stage1118_anchor_floor_preserves_certutil_decode_chain():
    score, hits = apply_anchor_score_floors(
        10.0,
        evaluate_chain_evidence(tags=physical_tag_evidence(("certutil_exec", "certutil_decode", "payload_decode_candidate", "cmd_exec"))),
        tags=physical_tag_evidence(("certutil_exec", "certutil_decode", "payload_decode_candidate", "cmd_exec")),
        stage="file",
    )

    assert score == 38.0
    assert hits == ["anchor:certutil_exec_support@stage2636_11020_chain_registry_v5"]


def test_stage1118_anchor_floor_preserves_injection_credential_priority():
    score, hits = apply_anchor_score_floors(
        12.0,
        evaluate_chain_evidence(tags=physical_tag_evidence(("process_injection", "memory_write", "thread_execution", "credential_dump_attempt"))),
        tags=physical_tag_evidence(("process_injection", "memory_write", "thread_execution", "credential_dump_attempt")),
        stage="file",
    )

    assert score == 50.0
    assert hits == ["anchor:credential_access@stage2636_11020_chain_registry_v5"]


def test_stage1118_anchor_floor_preserves_api_call_injection_chain():
    score, hits = apply_anchor_score_floors(
        4.0,
        evaluate_chain_evidence(api_calls=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]),
        tags=[],
        stage="file",
    )

    assert score == 4.0
    assert hits == []


def test_stage1118_anchor_floor_preserves_collection_and_patch_floors():
    score, hits = apply_anchor_score_floors(
        5.0,
        evaluate_chain_evidence(tags=physical_tag_evidence(("amsi_scanbuffer_patch", "process_exec", "service_create", "local_admin_add", "keylogging_behavior", "clipboard_access"))),
        tags=physical_tag_evidence(("amsi_scanbuffer_patch", "process_exec", "service_create", "local_admin_add", "keylogging_behavior", "clipboard_access")),
        stage="file",
    )

    assert score == 48.0
    assert hits == ["anchor:amsi_patch_static@stage2636_11020_chain_registry_v5"]


def test_stage1118_anchor_floor_preserves_archive_inner_tags():
    score, hits = apply_anchor_score_floors(
        2.0,
        evaluate_chain_evidence(tags=physical_tag_evidence(("archive_inner:shadowcopy_delete",))),
        tags=physical_tag_evidence(("archive_inner:shadowcopy_delete",)),
        stage="archive",
    )

    assert score == 50.0
    assert hits == [
        "anchor:ransomware_or_backup_deletion@stage2636_11020_chain_registry_v5",
        "anchor:shadowcopy_delete@stage2636_11020_chain_registry_v5",
    ]
