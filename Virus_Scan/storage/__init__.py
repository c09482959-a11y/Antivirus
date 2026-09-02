"""Canonical SQLite persistence authority public surface."""
from Virus_Scan.storage.candidate_store import (
    LearningCandidateStoreOwner,
    learning_candidate_store,
)
from Virus_Scan.storage.cache_repository import (
    ScanCacheHit,
    ScanCacheRepository,
    StaticAnalysisCacheHit,
    scan_cache_repository,
)
from Virus_Scan.storage.contracts import (
    CACHE_DATABASE_FILENAME,
    CANDIDATE_DATABASE_FILENAME,
    MODEL_DATABASE_FILENAME,
    DatabaseGeneration,
    DatabaseIntegrityResult,
    DatabasePaths,
)
from Virus_Scan.storage.model_authority import (
    AuthoritativeModelStateOwner,
    authoritative_model_state,
)
from Virus_Scan.storage.model_maintenance import (
    ModelDatabaseGrowthPolicy,
    ModelDatabaseMaintenanceResult,
    ModelDatabasePruneResult,
)
from Virus_Scan.storage.model_repository import ModelStateRepository
from Virus_Scan.storage.sqlite_lifecycle import (
    SQLiteLifecycleError,
    SQLiteLifecycleOwner,
    sqlite_lifecycle,
)

__all__ = (
    "AuthoritativeModelStateOwner",
    "CACHE_DATABASE_FILENAME",
    "CANDIDATE_DATABASE_FILENAME",
    "MODEL_DATABASE_FILENAME",
    "DatabaseGeneration",
    "DatabaseIntegrityResult",
    "DatabasePaths",
    "ModelStateRepository",
    "LearningCandidateStoreOwner",
    "ModelDatabaseGrowthPolicy",
    "ModelDatabaseMaintenanceResult",
    "ModelDatabasePruneResult",
    "SQLiteLifecycleError",
    "SQLiteLifecycleOwner",
    "ScanCacheHit",
    "ScanCacheRepository",
    "StaticAnalysisCacheHit",
    "scan_cache_repository",
    "authoritative_model_state",
    "learning_candidate_store",
    "sqlite_lifecycle",
)
