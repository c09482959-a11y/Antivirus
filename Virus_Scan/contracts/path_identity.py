"""Import-light path identity and scan-inclusion contracts.

Owned by contracts, not routing/core.  Core collection and routing policy both use
this file so path/schema utilities do not import routing at module or call time.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Iterable

DEFAULT_EXCLUDED_DIRS = frozenset({
    '.git', '.hg', '.svn', '__pycache__', '.pytest_cache',
    'Scan Logs', 'scan logs',
    'profiles', 'Yara', 'yara', 'Mitre', 'mitre',
    'VirusTotal', 'virustotal',
    'yara.cache', 'yaralight.cache', 'Temp', 'temp',
    'work_queue', 'file_results', 'pending', 'active', 'done', 'failed',
    '.staging', 'runs', 'state',
})
DEFAULT_EXCLUDED_FILES = frozenset({
    'scan_results.json',
    'virustotal_results.json', 'latest.json', 'report_manifest.json',
    'compiled_rules.yarc', 'scanlog', 'scanlog.txt', '.scanlock',
    '.umige-yara.lock', '.umige-mitre.lock', '.umige-virustotal.lock',
})
DEFAULT_EXCLUDED_SUFFIXES = frozenset({
    '.pyc', '.pyo', '.log', '.tmp', '.part', '.partial', '.download', '.bak', '.lock', '.lck', '.pid', '.tmpjson'
})
ROOTLESS_AMBIGUOUS_ARTIFACT_DIRS = frozenset({'temp', 'pending', 'active', 'done', 'failed'})
_PATH_ALLOWED = True

PATH_IDENTITY_TEXT_ERRORS = (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError)


def _path_exact_text(value: object, *, default_text: str = "") -> str:
    text = default_text
    try:
        if value is None:
            text = default_text
        elif isinstance(value, str):
            text = str.__str__(value)
        elif type(value) is bool:
            text = 'true' if value else 'false'
        elif type(value) is int:
            text = int.__str__(value)
        elif type(value) is float:
            text = float.__str__(value)
        elif type(value) in (bytes, bytearray):
            text = bytes(value).decode('utf-8', 'replace')
        elif isinstance(value, PurePath):
            text = PurePath.__str__(value)
    except PATH_IDENTITY_TEXT_ERRORS:
        text = default_text
    return text


def _path_text(value: object, *, default_text: str = "") -> str:
    return _path_exact_text(value, default_text=default_text).strip()

@dataclass(frozen=True)
class PathIdentity:
    raw: str
    name: str
    suffix: str
    parts: tuple[str, ...]
    exists: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw", _path_text(self.raw, default_text=""))
        object.__setattr__(self, "name", _path_text(self.name, default_text=""))
        object.__setattr__(self, "suffix", _path_text(self.suffix, default_text="").lower())
        parts = self.parts if type(self.parts) in (tuple, list) else ()
        object.__setattr__(self, "parts", tuple(_path_text(part, default_text="") for part in parts))
        exists_value = self.exists
        if isinstance(exists_value, bool):
            exists_flag = exists_value
        elif isinstance(exists_value, (int, float)):
            exists_flag = exists_value != 0
        else:
            exists_flag = False
        object.__setattr__(self, "exists", exists_flag)


@dataclass(frozen=True, slots=True)
class ScanPathPolicySnapshot:
    """Immutable scan-inclusion policy used at collection boundaries.

    The policy excludes generated scanner artifacts by relative scan-tree
    location, not by every absolute ancestor name.  A user may legitimately scan
    a game extracted under a host directory named ``Temp``; only directories
    inside the selected scan root that are scanner-owned artifacts are excluded.
    """

    excluded_dirs: frozenset[str]
    excluded_files: frozenset[str]
    excluded_suffixes: frozenset[str]

    def __post_init__(self) -> None:
        excluded_dirs = DEFAULT_EXCLUDED_DIRS if self.excluded_dirs is None else self.excluded_dirs
        excluded_files = DEFAULT_EXCLUDED_FILES if self.excluded_files is None else self.excluded_files
        excluded_suffixes = DEFAULT_EXCLUDED_SUFFIXES if self.excluded_suffixes is None else self.excluded_suffixes
        object.__setattr__(self, "excluded_dirs", frozenset(_path_text(item, default_text="") for item in excluded_dirs))
        object.__setattr__(self, "excluded_files", frozenset(_path_text(item, default_text="") for item in excluded_files))
        object.__setattr__(self, "excluded_suffixes", frozenset(_path_text(item, default_text="").lower() for item in excluded_suffixes))

    @classmethod
    def canonical(
        cls,
        *,
        excluded_dirs: Iterable[str] | None = None,
        excluded_files: Iterable[str] | None = None,
        excluded_suffixes: Iterable[str] | None = None,
    ) -> "ScanPathPolicySnapshot":
        dirs = DEFAULT_EXCLUDED_DIRS if excluded_dirs is None or type(excluded_dirs) not in (tuple, list, set, frozenset) else excluded_dirs
        files = DEFAULT_EXCLUDED_FILES if excluded_files is None or type(excluded_files) not in (tuple, list, set, frozenset) else excluded_files
        suffixes = DEFAULT_EXCLUDED_SUFFIXES if excluded_suffixes is None or type(excluded_suffixes) not in (tuple, list, set, frozenset) else excluded_suffixes
        return cls(
            frozenset(_path_text(item, default_text="") for item in dirs),
            frozenset(_path_text(item, default_text="") for item in files),
            frozenset(_path_text(item, default_text="").lower() for item in suffixes),
        )

    @property
    def normalized_dirs(self) -> frozenset[str]:
        return frozenset(item.casefold() for item in self.excluded_dirs)

    @property
    def normalized_files(self) -> frozenset[str]:
        return frozenset(item.casefold() for item in self.excluded_files)

    def allows(self, identity: PathIdentity) -> bool:
        return self.allows_relative(identity, relative_parts=identity.parts)

    def allows_relative(self, identity: PathIdentity, *, relative_parts: Iterable[str]) -> bool:
        safe_parts = relative_parts if type(relative_parts) in (tuple, list, set, frozenset) else ()
        normalized_parts = frozenset(_path_text(part, default_text="").casefold() for part in safe_parts)
        if normalized_parts & self.normalized_dirs:
            return False
        if identity.name.casefold() in self.normalized_files:
            return False
        if identity.suffix.lower() in self.excluded_suffixes:
            return False
        return _PATH_ALLOWED


def get_scan_extension(path: object) -> str:
    """Return the routed extension, including preserved game-asset suffixes.

    RPG Maker MV/MZ commonly preserves encrypted assets as ``.png_``/``.ogg_``.
    Treating the trailing underscore as the real extension made scheduler/cache
    older extension shortcuts disagreed with routing/extensions.py and pushed passive assets through
    slower generic/cache paths.  This contract is the canonical extension owner,
    so normalization belongs here.
    """
    extension = ''
    try:
        name = Path(_path_text(path, default_text='')).name.lower()
        if not name:
            return extension
        if name.endswith('_'):
            base = name[:-1]
            known = {
                '.ogg', '.oga', '.opus', '.mp3', '.wav', '.flac', '.m4a',
                '.aac', '.wma', '.png', '.jpg', '.jpeg', '.webp', '.gif',
                '.bmp', '.ttf', '.otf', '.fnt', '.json', '.txt', '.xml',
                '.rpy', '.rpyc', '.rpa', '.assets', '.asset', '.bundle',
                '.unity3d', '.resource', '.resources', '.ress'
            }
            for ext in sorted(known, key=len, reverse=True):
                if base.endswith(ext):
                    return ext
        extension = Path(name).suffix.lower()
    except (OSError, ValueError, TypeError) as exc:
        _ = exc
    return extension


def path_identity(path: object, *, require_exists: bool = False) -> PathIdentity:
    p = Path(_path_text(path, default_text=''))
    if require_exists:
        try:
            p = p.resolve(strict=True)
        except (OSError, ValueError, TypeError):
            p = p.absolute()
    return PathIdentity(_path_text(p, default_text=''), p.name, p.suffix.lower(), tuple(p.parts), p.exists())


def _relative_policy_parts(path: object, scan_root: object | None) -> tuple[str, ...]:
    candidate = Path(_path_text(path, default_text=''))
    if scan_root is None:
        return tuple(candidate.parts)
    try:
        return tuple(candidate.resolve(strict=False).relative_to(Path(_path_text(scan_root, default_text='')).resolve(strict=False)).parts)
    except (OSError, ValueError, TypeError):
        try:
            return tuple(candidate.relative_to(Path(_path_text(scan_root, default_text=''))).parts)
        except (OSError, ValueError, TypeError):
            return tuple(candidate.parts)


def should_include_scan_path(path: object, *, scan_root: object | None = None, excluded_dirs: Iterable[str] | None = None, excluded_files: Iterable[str] | None = None, excluded_suffixes: Iterable[str] | None = None) -> bool:
    """Canonical import-light path exclusion predicate.

    When ``scan_root`` is supplied, scanner artifact directories are matched only
    against the path relative to that root.  This preserves artifact exclusion
    inside the scan tree without rejecting legitimate user targets that live
    under host directories named Temp, profiles, Yara, or Scan Logs.
    """
    include_path = False
    try:
        ident = path_identity(path)
        relative_parts = _relative_policy_parts(path, scan_root)
        if scan_root is None:
            relative_parts = tuple(
                part for part in relative_parts
                if _path_text(part, default_text="").casefold() not in ROOTLESS_AMBIGUOUS_ARTIFACT_DIRS
            )
        include_path = ScanPathPolicySnapshot.canonical(
            excluded_dirs=excluded_dirs,
            excluded_files=excluded_files,
            excluded_suffixes=excluded_suffixes,
        ).allows_relative(ident, relative_parts=relative_parts)
    except (OSError, ValueError, TypeError) as exc:
        _ = exc
    return include_path
