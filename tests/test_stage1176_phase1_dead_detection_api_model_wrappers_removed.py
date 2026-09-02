from pathlib import Path

from Virus_Scan.contracts.api_behavior import API_GROUPS, build_api_regex, map_api_to_group
from Virus_Scan.models.profiles import behavior_vector_from_scan
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_dead_detection_api_model_wrappers_removed():
    api_dir = Path('Virus_Scan/detection/api')
    assert not (api_dir / 'api_pattern_contracts.py').exists()
    assert not (api_dir / 'model_behavior_contracts.py').exists()


def test_model_layer_uses_canonical_contract_owners_not_deleted_wrappers():
    for path in Path('Virus_Scan').rglob('*.py'):
        if 'Audit' in path.parts:
            continue
        source = path.read_text(encoding='utf-8')
        assert 'Virus_Scan.detection.api.api_pattern_contracts' not in source
        assert 'Virus_Scan.detection.api.model_behavior_contracts' not in source


def test_canonical_api_behavior_contract_still_available():
    assert API_GROUPS
    assert build_api_regex(API_GROUPS)
    assert map_api_to_group('CreateRemoteThread')


def test_canonical_behavior_vector_contract_still_model_owned():
    vector = behavior_vector_from_scan('renpy', 'sample.rpy', tags=physical_tag_evidence(('network_download', 'process_exec')))
    assert isinstance(vector, list)
    assert vector
    assert all(isinstance(item, float) for item in vector)
