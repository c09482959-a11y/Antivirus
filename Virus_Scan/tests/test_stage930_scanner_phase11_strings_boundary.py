from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scanners import strings



def test_strings_public_surface_has_no_private_detection_imports_and_is_bounded():
    source = read_python_file(Path('Virus_Scan/scanners/strings.py'))
    assert 'Virus_Scan.detection.' not in source
    assert len(source.splitlines()) <= 160
    assert strings._umige_ast_enriched_strings('x = "powershell"') == ['powershell']


def test_strings_scan_and_timeline_use_scanner_owned_contextual_tags():
    tags = strings.scan_strings(strings.ScanStringsRequest('regsvr32.exe powershell -enc AAAA', path='game/script.rpy'))
    assert 'regsvr32_exec' in tags
    assert 'encoded_powershell' in tags
    events = list(strings.iter_ordered_string_events('regsvr32.exe powershell -enc AAAA'))
    assert any(event[1]['tag'] == 'regsvr32_exec' for event in events)
