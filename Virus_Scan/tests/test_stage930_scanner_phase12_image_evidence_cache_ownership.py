from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scanners.image_evidence_cache import remember_scan_evidence



def test_image_scanner_uses_scanner_owned_evidence_cache_handoff():
    source = read_python_file(Path('Virus_Scan/scanners/image_scan.py'))
    assert 'Virus_Scan.detection.evidence.artifacts.scan_cache' not in source
    assert 'Virus_Scan.scanners.image_evidence_cache' in source
    result = remember_scan_evidence('sample.png', strings_blob='x', raw_sample=b'abc')
    assert result['ok'] is True
    assert result['cache_publication_request']['kind'] == 'scan_evidence_cache_write'
    assert result['cache_publication_request']['keys'] == ['raw_sample', 'strings_blob']
