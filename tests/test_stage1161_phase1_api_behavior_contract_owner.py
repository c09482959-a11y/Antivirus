from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.contracts import api_behavior
from Virus_Scan.models.init_parts import model_defaults_init



def test_stage1161_model_defaults_uses_repository_api_behavior_contract():
    source = read_python_file(Path('Virus_Scan/models/init_parts/model_defaults_init.py'))
    assert 'Virus_Scan.contracts.api_behavior' in source
    assert 'Virus_Scan.detection.api.api_pattern_contracts' not in source
    assert 'Virus_Scan.detection.contracts.api_contracts' not in source


def test_stage1161_repository_api_behavior_contract_preserves_api_projection():
    assert api_behavior.map_api_to_group('CreateProcessA') == 'process_execution'
    assert api_behavior.api_to_timeline_tag('CreateProcessA') == 'process_exec'
    assert api_behavior.api_to_timeline_tag('AmsiScanBuffer') == 'defense_evasion'
    regex = api_behavior.build_api_regex(api_behavior.API_GROUPS)
    assert regex.search('Call CreateRemoteThread then WriteProcessMemory')


def test_stage1161_detection_api_contract_wrapper_removed():
    assert not Path('Virus_Scan/detection/contracts/api_contracts.py').exists()


def test_stage1161_model_defaults_publish_canonical_api_groups():
    published = dict(model_defaults_init.init_model_defaults())
    assert dict(published['API_GROUPS']) == dict(api_behavior.API_GROUPS)
    assert published['API_REGEX'].search('CreateFile')
