"""Immutable contracts for the canonical SQLite persistence authority."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PosixPath, WindowsPath
from typing import Final, Literal

MODEL_DATABASE_SCHEMA_VERSION: Final[int] = 3
CANDIDATE_DATABASE_SCHEMA_VERSION: Final[int] = 4
CACHE_DATABASE_SCHEMA_VERSION: Final[int] = 1
MODEL_DATABASE_FILENAME: Final[str] = "model_state.sqlite3"
CANDIDATE_DATABASE_FILENAME: Final[str] = "learning_candidates.sqlite3"
CACHE_DATABASE_FILENAME: Final[str] = "scan_cache.sqlite3"
MODEL_DATABASE_APPLICATION_ID: Final[int] = 0x56534D44  # VSMD
CANDIDATE_DATABASE_APPLICATION_ID: Final[int] = 0x56534C43  # VSLC
CACHE_DATABASE_APPLICATION_ID: Final[int] = 0x56534344  # VSCD
DatabaseKind = Literal["model", "candidate", "cache"]


@dataclass(frozen=True, slots=True)
class DatabasePaths:
    profiles_dir: Path
    model_state: Path
    learning_candidates: Path
    scan_cache: Path

    @classmethod
    def from_profiles_dir(cls, profiles_dir: object) -> "DatabasePaths":
        if type(profiles_dir) in (Path, PosixPath, WindowsPath):
            root = Path(profiles_dir)
        elif (
            type(profiles_dir) is str
            and profiles_dir.strip()
            and profiles_dir.strip().lower() not in {"none", "null"}
        ):
            root = Path(profiles_dir)
        else:
            raise ValueError("profiles_directory_required")
        root = root.expanduser().absolute()
        return cls(
            profiles_dir=root,
            model_state=root / MODEL_DATABASE_FILENAME,
            learning_candidates=root / CANDIDATE_DATABASE_FILENAME,
            scan_cache=root / CACHE_DATABASE_FILENAME,
        )


@dataclass(frozen=True, slots=True)
class DatabaseGeneration:
    kind: DatabaseKind
    path: str
    schema_version: int
    schema_digest: str
    generation_id: str
    journal_mode: str
    synchronous: int
    foreign_keys: bool
    auto_vacuum: int
    busy_timeout_ms: int


@dataclass(frozen=True, slots=True)
class DatabaseIntegrityResult:
    kind: DatabaseKind
    ok: bool
    details: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DatabaseBackupArtifact:
    """One immutable SQLite-native known-good backup identity."""

    kind: DatabaseKind
    source_database_path: str
    backup_path: str
    backup_sha256: str
    schema_version: int
    schema_digest: str
    database_generation_id: str
    created_ns: int
    model_generation_id: str = ""
    model_generation_manifest_sha256: str = ""
    canonical_state_digest: str = ""

    def __post_init__(self) -> None:
        if self.kind not in {"model", "candidate", "cache"}:
            raise ValueError("database_backup_kind_invalid")
        if type(self.source_database_path) is not str or not self.source_database_path:
            raise ValueError("database_backup_source_path_invalid")
        if type(self.backup_path) is not str or not self.backup_path:
            raise ValueError("database_backup_path_invalid")
        if (
            type(self.backup_sha256) is not str
            or len(self.backup_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in self.backup_sha256)
        ):
            raise ValueError("database_backup_sha256_invalid")
        if type(self.schema_version) is not int or self.schema_version <= 0:
            raise ValueError("database_backup_schema_version_invalid")
        if (
            type(self.schema_digest) is not str
            or len(self.schema_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in self.schema_digest)
        ):
            raise ValueError("database_backup_schema_digest_invalid")
        if (
            type(self.database_generation_id) is not str
            or len(self.database_generation_id) != 64
            or any(ch not in "0123456789abcdef" for ch in self.database_generation_id)
        ):
            raise ValueError("database_backup_generation_id_invalid")
        if type(self.created_ns) is not int or self.created_ns < 0:
            raise ValueError("database_backup_created_time_invalid")
        model_fields = (
            self.model_generation_id,
            self.model_generation_manifest_sha256,
            self.canonical_state_digest,
        )
        if self.kind == "model":
            if any(
                type(value) is not str
                or len(value) != 64
                or any(ch not in "0123456789abcdef" for ch in value)
                for value in model_fields
            ):
                raise ValueError("database_backup_model_generation_identity_invalid")
        elif any(model_fields):
            raise ValueError("database_backup_non_model_generation_identity_rejected")


__all__ = (
    "CACHE_DATABASE_APPLICATION_ID",
    "CANDIDATE_DATABASE_APPLICATION_ID",
    "CANDIDATE_DATABASE_FILENAME",
    "CANDIDATE_DATABASE_SCHEMA_VERSION",
    "CACHE_DATABASE_FILENAME",
    "CACHE_DATABASE_SCHEMA_VERSION",
    "DatabaseBackupArtifact",
    "DatabaseGeneration",
    "DatabaseIntegrityResult",
    "DatabaseKind",
    "DatabasePaths",
    "MODEL_DATABASE_APPLICATION_ID",
    "MODEL_DATABASE_FILENAME",
    "MODEL_DATABASE_SCHEMA_VERSION",
)
