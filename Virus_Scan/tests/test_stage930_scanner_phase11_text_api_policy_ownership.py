from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scanners.config.loader import load_text_policy_snapshot
from Virus_Scan.scanners.text_api_policy import API_GROUPS, build_api_regex, map_api_to_group



def test_text_api_policy_is_scanner_config_owned():
    source = read_python_file(Path('Virus_Scan/scanners/text_api_policy.py'))
    assert 'Virus_Scan.detection.contracts.api_contracts' not in source
    assert 'from Virus_Scan.scanners.text_policy import API_GROUPS' in source
    snapshot = load_text_policy_snapshot()
    assert 'process_execution' in snapshot.api_groups
    assert 'CreateProcessA' in snapshot.api_groups['process_execution']


def test_text_api_policy_mapping_and_regex_are_case_insensitive():
    regex = build_api_regex(API_GROUPS)
    assert regex.search('call createprocessa now')
    assert map_api_to_group('CreateProcessA') == 'process_execution'
    assert map_api_to_group('createprocessa') == 'process_execution'
