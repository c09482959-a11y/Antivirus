"""models package initializer.

Stage 12: subsystem runtime initialization moved here from Virus_Scan.init_runtime.
Functionality remains in this package; main/top_level only orchestrate calls.
"""

# ---- moved from init_runtime/profiles.py ----
# Top-level state initialization extracted from v27c.
# Normal Python code; no exec-string body.
import os
from threading import RLock
from Virus_Scan.runtime.init_state import publish_init_values
from Virus_Scan.contracts.env_config import str_env



from Virus_Scan.runtime.config_state import configure_ilspy_path
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.runtime.resource_paths import program_root


def init_profiles() -> object:
    BASE_DIR = str_env('UMIGE_BASE_DIR', '') or get_init_value('BASE_DIR') or str(program_root())
    PROFILES_DIR = os.path.join(BASE_DIR, 'profiles')
    DEFAULT_ENGINES = ['renpy', 'rpgm', 'unity', 'media', 'other']
    CLI_ENGINE_HINT = 'auto'
    SCAN_ENGINE_HINT = 'auto'
    SCAN_ENGINE_HINT_CONTEXT = {}
    ILSPY_PATH = configure_ilspy_path(None)
    USE_ILSPY = False
    ILSPY_TIMEOUT_SEC = 60
    ILSPY_DUMP_ROOT = None
    ILSPY_CACHE = {}
    PROFILE_FILE_LOCK = RLock()
    PROFILE_FLUSH_EVERY = 25
    BULK_DEFER_PROFILE_WRITES = False
    BULK_PROFILE_FLUSH_EVERY = 1000000000
    BENIGN_CANDIDATE_LOCK = RLock()
    PROMOTE_AFTER_CLEAN_OBS = 3
    MAX_RISK_FOR_STAGING = 25.0
    MAX_RISK_FOR_PROMOTION = 20.0
    MIN_PROMOTION_SPREAD_DAYS = 2.0
    BENIGN_STAGE_FLUSH_EVERY = 250
    BULK_DEFER_BENIGN_STAGE_WRITES = True

    profile_learning_state = (
        ('PROFILES_DIR', PROFILES_DIR),
        ('DEFAULT_ENGINES', DEFAULT_ENGINES),
        ('CLI_ENGINE_HINT', CLI_ENGINE_HINT),
        ('SCAN_ENGINE_HINT', SCAN_ENGINE_HINT),
        ('SCAN_ENGINE_HINT_CONTEXT', SCAN_ENGINE_HINT_CONTEXT),
        ('ILSPY_PATH', ILSPY_PATH),
        ('USE_ILSPY', USE_ILSPY),
        ('ILSPY_TIMEOUT_SEC', ILSPY_TIMEOUT_SEC),
        ('ILSPY_DUMP_ROOT', ILSPY_DUMP_ROOT),
        ('ILSPY_CACHE', ILSPY_CACHE),
        ('PROFILE_FILE_LOCK', PROFILE_FILE_LOCK),
        ('PROFILE_FLUSH_EVERY', PROFILE_FLUSH_EVERY),
        ('BULK_DEFER_PROFILE_WRITES', BULK_DEFER_PROFILE_WRITES),
        ('BULK_PROFILE_FLUSH_EVERY', BULK_PROFILE_FLUSH_EVERY),
        ('BENIGN_CANDIDATE_LOCK', BENIGN_CANDIDATE_LOCK),
        ('PROMOTE_AFTER_CLEAN_OBS', PROMOTE_AFTER_CLEAN_OBS),
        ('MAX_RISK_FOR_STAGING', MAX_RISK_FOR_STAGING),
        ('MAX_RISK_FOR_PROMOTION', MAX_RISK_FOR_PROMOTION),
        ('MIN_PROMOTION_SPREAD_DAYS', MIN_PROMOTION_SPREAD_DAYS),
        ('BENIGN_STAGE_FLUSH_EVERY', BENIGN_STAGE_FLUSH_EVERY),
        ('BULK_DEFER_BENIGN_STAGE_WRITES', BULK_DEFER_BENIGN_STAGE_WRITES)
    )
    publish_init_values(profile_learning_state)
    return publish_init_values(())


__all__ = ("init_profiles",)
