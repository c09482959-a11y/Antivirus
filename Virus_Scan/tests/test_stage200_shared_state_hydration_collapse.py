from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

from Virus_Scan.core.init_parts.cache_init import init_caches, init_finalize
from Virus_Scan.runtime.init_state import get_init_value, init_state_snapshot


def test_cache_init_uses_canonical_init_publication_without_sync_fanout_calls():
    source = (PROJECT_ROOT / 'core/init_parts/cache_init.py').read_text()
    assert 'sync' + '_modules()' not in source
    assert 'sync' + '_modules' not in source
    assert "publish_init_values(tuple(dict.items(cache_state)))" in source
    assert "MAX_COUNTER_KEYS" in source


def test_cache_init_publishes_values_directly_without_wrapper_class():
    before = init_state_snapshot().get('generation', 0)
    state = init_caches()
    after = init_state_snapshot().get('generation', 0)
    assert get_init_value('MAX_COUNTER_KEYS') == 5000
    assert get_init_value('CACHE_TTL') == 300
    assert 'MAX_COUNTER_KEYS' in state
    assert after > before


def test_runtime_finalizer_function_sets_top_level_without_sync_fanout():
    before = init_state_snapshot().get('generation', 0)
    init_finalize()
    after = init_state_snapshot().get('generation', 0)
    assert get_init_value('_TOP_LEVEL_INITIALIZED') is True
    assert after > before
