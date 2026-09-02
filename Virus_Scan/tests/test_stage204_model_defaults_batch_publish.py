from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SET_SHARED = "set" + "_shared"
SYNC_MODULES = "sync" + "_modules"


def test_model_defaults_uses_batch_publication_not_per_symbol_publication():
    source = (PROJECT_ROOT / 'models/init_parts/model_defaults_init.py').read_text(encoding='utf-8')
    assert 'publish_init_values((' in source
    assert f"{SET_SHARED}('ANALYTICAL_EVIDENCE_SCHEMA_VERSION'" not in source
    assert f"{SET_SHARED}('TEMPORAL_EVENTS'" not in source
    assert SYNC_MODULES not in source


from Virus_Scan.models.init_parts.model_defaults_init import init_model_defaults


def test_model_defaults_batch_publish_preserves_non_temporal_state_keys():

    state = init_model_defaults()
    assert state['ANALYTICAL_EVIDENCE_SCHEMA_VERSION'] == '2.1'
    assert state['CALIBRATED_SCORE_VERSION'] == 'log_odds_v4_adaptive_calibrated'
    assert 'TEMPORAL_EVENTS' not in state
    assert 'TEMPORAL_PHASE_ORDER' not in state
    assert 'TEMPORAL_HIGH_RISK_TAGS' not in state
    assert 'ENGINE_FILE_CONTEXT_CUES' in state
