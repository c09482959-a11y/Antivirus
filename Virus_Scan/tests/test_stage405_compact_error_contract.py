from Virus_Scan.publication import json_writer
from Virus_Scan.publication.json_writer import compact_result_record


def test_compact_error_branch_preserves_full_json_audit_contract():
    compact = json_writer.build_compact_error_record(
        json_writer.normalize_compact_result_record(
            {
                'path': '/tmp/sample.bin',
                'score': 25,
                'classification': 'MEDIUM',
                'tags': ['embedded_pe_payload', 'polyglot_artifact'],
                'container_engine_confidence': 0.75,
                'artifact_engine_confidence': 0.5,
                'explanation': {'reasons': ['embedded payload evidence']},
            }
        ),
        RuntimeError('forced compact failure'),
    )
    for field in (
        'filename',
        'container_engine_confidence',
        'artifact_engine_confidence',
        'binary_failover_tags',
        'stego_findings',
        'dotnet_findings',
        'ilspy_findings',
        'dncil_findings',
    ):
        assert field in compact
    assert compact['filename'] == 'sample.bin'
    assert compact['compact_error'] is True
    assert compact['final_status'] == 'compact_record_error'
    assert compact['evidence'] == ['compact_record_error:RuntimeError']


def test_normal_compact_record_still_carries_full_json_audit_contract():
    record = compact_result_record({
        'path': '/tmp/sample.bin',
        'score': 25,
        'classification': 'MEDIUM',
        'tags': ['embedded_pe_payload', 'polyglot_artifact'],
        'explanation': {'reasons': ['embedded payload evidence']},
    })
    for field in (
        'filename', 'duration', 'duration_seconds', 'scan_duration_seconds',
        'yara', 'entropy', 'temporal', 'markov', 'clustering', 'graph',
        'binary_failover_tags', 'stego_findings', 'dotnet_findings',
        'ilspy_findings', 'dncil_findings', 'evidence_snippets',
    ):
        assert field in record
    assert record['filename'] == 'sample.bin'
    assert record['evidence_snippets']
