"""Score-explanation failure evidence attachment owner."""

from Virus_Scan.detection.evidence.failure_evidence import failure_evidence_payload
from Virus_Scan.detection.scoring.full_analysis.boundaries import full_analysis_sequence


def attach_failure_evidence(explanation: object, failure_evidence: object) -> object:
    """Attach JSON/replay-visible detection failures to a mutable explanation."""
    failure_records = full_analysis_sequence(failure_evidence)
    if len(failure_records) == 0:
        return explanation
    if not isinstance(explanation, dict):
        explanation = {'unstructured_explanation': explanation}
    payload = failure_evidence_payload(failure_records)
    explanation['detection_failures'] = payload['failures']
    explanation['scanner_degraded'] = bool(payload['degraded'])
    explanation['confidence_degraded'] = bool(payload['confidence_degraded'])
    explanation.setdefault('reasons', [])
    if isinstance(explanation['reasons'], list):
        explanation['reasons'].append('recoverable_detection_stage_degraded')
    return explanation


__all__ = ('attach_failure_evidence',)
