import pytest
from Virus_Scan.contracts.result_record import ResultEvidenceSnapshot, validate_result_record_invariants


def _base_high_record(**extra):
    record = {
        'file': 'sample.bin',
        'classification': 'high',
        'score': 85,
        'tags': [],
        'chains': [],
        'yara_signals': [],
        'decoded_evidence_snippets': [],
    }
    record.update(extra)
    return record


@pytest.mark.parametrize('field,value', [
    ('temporal_signals', [{'anomaly': 0.9}]),
    ('markov_sequence_signals', [{'transition': 'rare'}]),
    ('clustering_signals', [{'cluster': 'outlier'}]),
    ('graph_signals', [{'risk': 0.8}]),
    ('entropy_signals', [{'entropy': 7.8}]),
    ('archive_container_signals', [{'embedded': 'pe'}]),
    ('fingerprint_evidence', [{'engine_mismatch': True}]),
])
def test_high_risk_result_accepts_canonical_model_evidence_fields(field, value):
    record = _base_high_record(**{field: value})
    assert validate_result_record_invariants(record, context='stage351') is True
    assert ResultEvidenceSnapshot.from_record(record).has_evidence is True


def test_high_risk_result_without_any_evidence_still_hard_fails():
    with pytest.raises(ValueError, match='high-risk result missing forensic evidence'):
        validate_result_record_invariants(_base_high_record(), context='stage351')


def test_result_identity_invariant_rejects_conflicting_file_path_values():
    record = _base_high_record(tags=['evidence'], file='a/sample.bin', path='b/sample.bin')
    with pytest.raises(ValueError, match='conflicting file identity'):
        validate_result_record_invariants(record, context='stage351')
