from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts import api_behavior
from Virus_Scan.contracts.path_identity import get_scan_extension


def _production_python_sources() -> tuple[Path, ...]:
    roots = (Path('Virus_Scan/models'), Path('Virus_Scan/detection'), Path('Virus_Scan/runtime'), Path('Virus_Scan/publication'), Path('Virus_Scan/replay'))
    out: list[Path] = []
    for root in roots:
        if root.exists():
            out.extend(path for path in root.rglob('*.py') if '__pycache__' not in path.parts)
    return tuple(sorted(out))


def test_stage1208_detection_api_behavior_wrapper_is_removed():
    assert not Path('Virus_Scan/detection/contracts/api_contracts.py').exists()


def test_stage1208_model_layer_sources_use_canonical_api_behavior_contract():
    offenders = []
    for path in _production_python_sources():
        source = path.read_text(encoding='utf-8')
        if 'Virus_Scan.detection.contracts.api_contracts' in source:
            offenders.append(str(path))
    assert offenders == []


def test_stage1208_canonical_api_behavior_contract_still_projects_expected_tags():
    assert api_behavior.map_api_to_group('CreateProcessA') == 'process_execution'
    assert api_behavior.map_api_to_group('createprocessa') == 'process_execution'
    assert api_behavior.api_to_timeline_tag('CreateRemoteThread') == 'thread_execution'
    assert api_behavior.api_to_timeline_tag('AmsiScanBuffer') == 'defense_evasion'
    assert api_behavior.build_api_regex(api_behavior.API_GROUPS).search('WriteProcessMemory')


def test_stage1208_detection_path_identity_wrapper_is_removed():
    assert not Path('Virus_Scan/detection/contracts/path_identity.py').exists()


def test_stage1208_detection_sources_use_canonical_path_identity_contract():
    offenders = []
    for path in _production_python_sources():
        source = path.read_text(encoding='utf-8')
        if 'Virus_Scan.detection.contracts.path_identity' in source:
            offenders.append(str(path))
    assert offenders == []


def test_stage1208_canonical_path_identity_preserves_rpgm_encrypted_asset_extensions():
    assert get_scan_extension('Audio/BGM/theme.ogg_') == '.ogg'
    assert get_scan_extension('www/img/picture.PNG_') == '.png'
    assert get_scan_extension('Game.rgss3a') == '.rgss3a'
    assert get_scan_extension('archive.unknown_') == '.unknown_'
    assert get_scan_extension('') == ''
