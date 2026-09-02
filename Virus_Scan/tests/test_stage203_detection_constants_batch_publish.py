from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SET_SHARED = "set" + "_shared"


def test_detection_constants_uses_batch_publication_not_per_symbol_publication():
    source = (PROJECT_ROOT / 'detection/registries/detection_constants.py').read_text(encoding='utf-8')
    assert 'publish_init_values((' in source
    assert f"{SET_SHARED}('CONTEXTUAL_BASELINE_VERSION'" not in source
    assert f"{SET_SHARED}('TAG_RISK_SCORES'" not in source
    assert 'legacy non-detection readers' not in source
    assert 'TAG_ALIAS_REPORTING_MAP = DEFAULT_DETECTION_REGISTRY_SNAPSHOT.value' not in source
    assert '"TAG_ALIAS_REPORTING_MAP",' not in source


from Virus_Scan.detection.registries.detection_constants import init_detection_constants


def test_detection_constants_batch_publish_preserves_state_keys():

    state = init_detection_constants()
    assert state['CONTEXTUAL_BASELINE_VERSION'] == 1
    assert 'TAG_RISK_SCORES' in state
    assert 'BUCKET_TAGS' in state
    assert 'STRUCTURAL_NOISE_TAGS' in state
