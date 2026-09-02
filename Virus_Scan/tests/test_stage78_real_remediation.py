from Virus_Scan.contracts.telemetry import record_detector_error as telemetry_rec
from Virus_Scan.core.logging import record_detector_error as core_rec


def test_telemetry_record_detector_error_accepts_context_keywords():
    rec = telemetry_rec('unity', RuntimeError('boom'), path='x.dll', stage='scanner')
    assert rec['context']['path'] == 'x.dll'
    assert rec['context']['stage'] == 'scanner'


def test_core_record_detector_error_accepts_context_keywords():
    rec = core_rec('unity', RuntimeError('boom'), path='x.dll', stage='scanner')

    assert rec['detector'] == 'unity'
    assert rec['context']['path'] == 'x.dll'
    assert rec['context']['stage'] == 'scanner'
    assert 'boom' in rec['error']
