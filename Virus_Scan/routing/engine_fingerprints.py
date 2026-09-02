"""Canonical immutable engine fingerprint scoring.

Policy tables live in :mod:`Virus_Scan.routing.engine_fingerprint_policy` so the
runtime scorer remains bounded and owns behavior rather than large data tables.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, TypeAlias

from Virus_Scan.routing.path_boundaries import routing_path, routing_path_text

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.contracts.path_identity import should_include_scan_path
from Virus_Scan.routing.engine_fingerprint_policy import (
    DIRECT_CONTAINER_DIRECTORY_MARKERS,
    ENGINE_FINGERPRINTS,
    ENGINE_NAMES,
    MEDIA_CONTENT_MARKERS,
    MEDIA_EXTENSIONS,
    MEDIA_FILENAMES,
    MEDIA_PATH_MARKERS,
    MEDIA_PATTERNS,
    RENPY_CONTENT_MARKERS,
    RENPY_EXACT_PATHS,
    RENPY_EXTENSIONS,
    RENPY_FILENAMES,
    RENPY_PATH_MARKERS,
    RENPY_PATTERNS,
    RPGM_CONTENT_MARKERS,
    RPGM_EXTENSIONS,
    RPGM_FILENAMES,
    RPGM_PATH_MARKERS,
    RPGM_PATTERNS,
    UNITY_CONTENT_MARKERS,
    UNITY_EXTENSIONS,
    UNITY_FILENAMES,
    UNITY_PATH_MARKERS,
    UNITY_PATTERNS,
)


PLR2004N0_35 = 0.35
PLR2004N262144 = 262144
PLR2004N4096 = 4096

@dataclass(frozen=True)
class EngineFingerprint:
    engine: str
    score: float
    confidence: float
    evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ContainerFileSample:
    data: bytes
    unavailable_reason: str = ""

    def __post_init__(self) -> None:
        if type(self.data) is not bytes or type(self.unavailable_reason) is not str:
            raise TypeError("container_file_sample_invalid")


ContainerSampleCache: TypeAlias = MutableMapping[str, ContainerFileSample]

CueMap: TypeAlias = Mapping[str, tuple[str, ...]]


def _engine_fingerprint_items(value: Mapping[str, EngineFingerprint]) -> tuple[tuple[str, EngineFingerprint], ...]:
    items = no_hook_mapping_items(value)
    if items is None:
        return ()
    out: list[tuple[str, EngineFingerprint]] = []
    for engine, fingerprint in items:
        if type(engine) is str and type(fingerprint) is EngineFingerprint:
            out.append((engine, fingerprint))
    return tuple(out)


def _direct_marker_items(value: Mapping[str, tuple[str, ...]]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    items = no_hook_mapping_items(value)
    if items is None:
        return ()
    out: list[tuple[str, tuple[str, ...]]] = []
    for engine, markers in items:
        if type(engine) is str and type(markers) is tuple and all(type(marker) is str for marker in markers):
            out.append((engine, markers))
    return tuple(out)


def _cue_items(value: Mapping[str, CueMap]) -> tuple[tuple[str, CueMap], ...]:
    items = no_hook_mapping_items(value)
    if items is None:
        return ()
    out: list[tuple[str, CueMap]] = []
    for engine, cues in items:
        if type(engine) is str and isinstance(cues, Mapping):
            out.append((engine, cues))
    return tuple(out)


def score_direct_container_directory(name: object) -> dict[str, EngineFingerprint]:
    text, reason = routing_path_text(name, missing_reason="routing_directory_name_missing", unsupported_reason="unsafe_routing_directory_name_rejected")
    if reason:
        return {}
    normalized = text.lower().strip()
    if not normalized:
        return {}
    out: dict[str, EngineFingerprint] = {}
    for engine, markers in _direct_marker_items(DIRECT_CONTAINER_DIRECTORY_MARKERS):
        if normalized in markers or (engine == "unity" and normalized.endswith("_data")):
            out[engine] = EngineFingerprint(engine, 12.0, 1.0, (str.__add__("direct_dir:", normalized),))
    return out


def _norm_path(path: object) -> str:
    text, reason = routing_path_text(path, missing_reason="routing_path_missing", unsupported_reason="unsafe_routing_path_rejected")
    if reason:
        return ""
    return text.replace("\\", "/").lower()


def _relative_marker(path: object, root: object | None = None) -> str:
    text = _norm_path(path)
    if root is not None:
        root_text = _norm_path(root).rstrip("/")
        if root_text and text.startswith(root_text + "/"):
            text = text[len(root_text) + 1:]
    return text


def _content_text(sample: bytes | str | None) -> str:
    if type(sample) is bytes:
        return sample[:8192].decode("latin1", errors="ignore").lower()
    if isinstance(sample, str):
        return str.__str__(sample)[:8192].lower()
    return ""


def _score_cue_set(engine: str, cues: Mapping[str, tuple[str, ...]], suffix: str, name: str, rel: str, text: str) -> EngineFingerprint | None:
    score = 0.0
    evidence: list[str] = []
    rel_for_match = rel.strip("/")
    if suffix and suffix in cues["extensions"]:
        score += 3.0
        evidence.append(str.__add__("extension:", suffix))
    if name in cues["filenames"]:
        score += 8.0
        evidence.append(str.__add__("filename:", name))
    for exact in cues["exact_paths"]:
        if rel.endswith(exact):
            score += 6.0
            evidence.append(str.__add__("path:", exact))
    for pattern in cues["patterns"]:
        if fnmatch(rel_for_match, pattern):
            score += 3.5
            evidence.append(str.__add__("pattern:", pattern))
    for marker in cues["path_markers"]:
        if marker in str.__add__("/", rel):
            score += 2.5
            evidence.append(str.__add__("path_marker:", marker.strip("/")))
    for marker in cues["content_markers"]:
        if marker in text:
            score += 2.0
            evidence.append(str.__add__("content:", marker))
    if score <= 0.0:
        return None
    return EngineFingerprint(engine, score, 0.0, tuple(evidence[:32]))


def score_engine_for_path(path: object, *, root: object | None = None, sample: bytes | str | None = None) -> dict[str, EngineFingerprint]:
    normalized = _norm_path(path)
    rel = _relative_marker(path, root)
    name = Path(normalized).name
    suffix = Path(name).suffix.lower()
    text = _content_text(sample)
    scored = tuple(
        fp for engine, cues in _cue_items(ENGINE_FINGERPRINTS)
        if (fp := _score_cue_set(engine, cues, suffix, name, rel, text)) is not None
    )
    total = sum(fp.score for fp in scored)
    if total <= 0.0:
        return {"other": EngineFingerprint("other", 0.1, 1.0, ("no_engine_fingerprint",))}
    return {
        fp.engine: EngineFingerprint(fp.engine, fp.score, min(1.0, fp.score / max(total, fp.score)), fp.evidence)
        for fp in scored
    }


def choose_engine(fingerprints: Mapping[str, EngineFingerprint]) -> EngineFingerprint:
    items = _engine_fingerprint_items(fingerprints)
    if not items:
        return EngineFingerprint("other", 0.1, 1.0, ("no_engine_fingerprint",))
    return max((fp for _engine, fp in items), key=lambda item: (item.score, item.confidence, item.engine))


def _iter_fingerprint_paths(root_path: Path) -> Iterable[Path]:
    if not root_path.is_dir():
        if should_include_scan_path(root_path, scan_root=root_path.parent):
            return (root_path,)
        return ()
    collected = []
    for candidate in sorted(root_path.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if not (candidate.is_file() or candidate.is_dir()):
            continue
        if candidate.is_file() and not should_include_scan_path(candidate, scan_root=root_path):
            continue
        collected.append(candidate)
        if len(collected) >= PLR2004N4096:
            break
    return tuple(collected)


def container_file_sample(path: Path, sample_cache: ContainerSampleCache) -> ContainerFileSample:
    key = path.as_posix()
    cached = sample_cache.get(key)
    if type(cached) is ContainerFileSample:
        return cached
    try:
        if not path.is_file() or path.stat().st_size > PLR2004N262144:
            sample = ContainerFileSample(b"")
        else:
            with path.open("rb") as handle:
                sample = ContainerFileSample(handle.read(8192))
    except (OSError, AttributeError, TypeError, ValueError) as exc:
        sample = ContainerFileSample(b"", type(exc).__name__ or "container_sample_unavailable")
    sample_cache[key] = sample
    return sample


def _small_file_sample(path: Path, sample_cache: ContainerSampleCache) -> bytes:
    return container_file_sample(path, sample_cache).data


def fingerprint_container(
    root: object, *, sample_cache: ContainerSampleCache | None = None,
) -> EngineFingerprint:
    root_path, root_reason = routing_path(root, missing_reason="container_root_missing", unsupported_reason="unsafe_container_root_rejected")
    if root_reason or root_path is None:
        return EngineFingerprint("other", 0.1, 1.0, (root_reason or "container_root_unavailable",))
    owned_sample_cache: ContainerSampleCache = {} if sample_cache is None else sample_cache
    scores: dict[str, float] = {"renpy": 0.0, "rpgm": 0.0, "unity": 0.0, "media": 0.0}
    evidence: dict[str, list[str]] = {"renpy": [], "rpgm": [], "unity": [], "media": []}
    for candidate in _iter_fingerprint_paths(root_path):
        for engine, fp in _engine_fingerprint_items(
            score_engine_for_path(candidate, root=root_path, sample=_small_file_sample(candidate, owned_sample_cache))
        ):
            if engine in scores:
                scores[engine] += fp.score
                evidence[engine].extend(fp.evidence[:8])
    total = sum(dict.get(scores, key, 0.0) for key in tuple(dict.keys(scores)))
    if total <= 0.0:
        return EngineFingerprint("other", 0.1, 1.0, ("no_container_engine_fingerprint",))
    best = max(tuple(dict.keys(scores)), key=lambda key: dict.get(scores, key, 0.0))
    confidence = min(1.0, scores[best] / total) if total else 0.0
    if confidence < PLR2004N0_35:
        return EngineFingerprint("other", scores[best], confidence, ('weak_container_engine_fingerprint', *tuple(evidence[best][:16])))
    return EngineFingerprint(best, scores[best], confidence, tuple(dict.fromkeys(evidence[best]))[:48])


__all__ = (
    "DIRECT_CONTAINER_DIRECTORY_MARKERS",
    "ENGINE_FINGERPRINTS",
    "ENGINE_NAMES",
    "MEDIA_CONTENT_MARKERS",
    "MEDIA_EXTENSIONS",
    "MEDIA_FILENAMES",
    "MEDIA_PATH_MARKERS",
    "MEDIA_PATTERNS",
    "RENPY_CONTENT_MARKERS",
    "RENPY_EXACT_PATHS",
    "RENPY_EXTENSIONS",
    "RENPY_FILENAMES",
    "RENPY_PATH_MARKERS",
    "RENPY_PATTERNS",
    "RPGM_CONTENT_MARKERS",
    "RPGM_EXTENSIONS",
    "RPGM_FILENAMES",
    "RPGM_PATH_MARKERS",
    "RPGM_PATTERNS",
    "UNITY_CONTENT_MARKERS",
    "UNITY_EXTENSIONS",
    "UNITY_FILENAMES",
    "UNITY_PATH_MARKERS",
    "UNITY_PATTERNS",
    "ContainerFileSample",
    "ContainerSampleCache",
    "EngineFingerprint",
    "choose_engine",
    "container_file_sample",
    "fingerprint_container",
    "score_direct_container_directory",
    "score_engine_for_path",
)
