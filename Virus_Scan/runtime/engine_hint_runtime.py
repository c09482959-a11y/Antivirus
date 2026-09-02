"""Import-light runtime engine hint resolver.

Startup path configuration cannot depend on the full routing/detection package:
that creates a cycle through ``models.profiles`` back into ``core.paths``.  This
module provides the deterministic, import-light subset needed at CLI bootstrap
using explicit file-system evidence only.
"""
from __future__ import annotations

import os
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.contracts.artifact_read_snapshot import read_artifact_prefix
from Virus_Scan.contracts.path_identity import should_include_scan_path
from Virus_Scan.runtime.governance_inputs import (
    runtime_float,
    runtime_input_rejection,
    runtime_int,
    runtime_mapping,
    runtime_text,
)

PLR2004N0_8 = 0.8

_ENGINE_KEYS = ('unity', 'renpy', 'rpgm', 'media', 'unknown')
_MEDIA_MAGIC_PREFIXES = (
    b'\x89PNG\r\n\x1a\n',
    b'\xff\xd8\xff',
    b'GIF87a',
    b'GIF89a',
    b'RIFF',
    b'OggS',
    b'fLaC',
    b'ID3',
)
_MEDIA_MAGIC_OFFSETS = (b'ftyp',)
_STDLIB_PATH_TYPES = (Path, PosixPath, WindowsPath, PurePosixPath, PureWindowsPath)


def _startup_reason(prefix: str, value: object) -> str:
    return str.__str__(prefix) + ":" + no_hook_type_name(value)


def _startup_context_field(key: object) -> str:
    if type(key) is str:
        return "startup_engine_context_" + str.__str__(key)
    return "startup_engine_context_input_rejected"


def _media_magic_result(path: Path) -> tuple[bool, Mapping[str, object] | None]:
    try:
        header = read_artifact_prefix(path, 32)
    except (OSError, RuntimeError, ValueError) as exc:
        return (
            False,
            runtime_input_rejection(
                "startup_engine_media_magic",
                path,
                _startup_reason("startup_engine_media_magic_unavailable", exc),
            ),
        )
    if any(header.startswith(prefix) for prefix in _MEDIA_MAGIC_PREFIXES):
        return True, None
    return any(marker in header[:16] for marker in _MEDIA_MAGIC_OFFSETS), None


def _has_media_magic(path: Path) -> bool:
    matched, _evidence = _media_magic_result(path)
    return matched


def _empty_context(
    evidence: tuple[Mapping[str, object], ...] = (),
) -> dict[str, object]:
    context: dict[str, object] = {
        'unity': 0.0,
        'renpy': 0.0,
        'rpgm': 0.0,
        'media': 0.0,
        'unknown': 1.0,
    }
    if evidence:
        context["input_evidence"] = evidence
    return context


def _normalize(
    scores: dict[str, float],
    evidence: tuple[Mapping[str, object], ...] = (),
) -> dict[str, object]:
    total = sum(max(0.0, scores.get(key, 0.0)) for key in _ENGINE_KEYS)
    if total <= 0.0:
        return _empty_context(evidence)
    context: dict[str, object] = {
        key: max(0.0, scores.get(key, 0.0)) / total
        for key in _ENGINE_KEYS
    }
    if evidence:
        context["input_evidence"] = evidence
    return context


def _engine_hint_to_context(engine: object) -> dict[str, object]:
    engine, issues = runtime_text(
        engine, field_name="startup_engine_hint", default="unknown"
    )
    engine = engine.lower().strip()
    if engine == 'other':
        engine = 'unknown'
    if engine not in _ENGINE_KEYS:
        issues += (
            runtime_input_rejection(
                "startup_engine_hint",
                engine,
                "startup_engine_hint_unknown",
            ),
        )
        return _empty_context(issues)
    context: dict[str, object] = {
        key: (1.0 if key == engine else 0.0)
        for key in _ENGINE_KEYS
    }
    if issues:
        context["input_evidence"] = issues
    return context


def _startup_path(value: object) -> Path:
    if type(value) in _STDLIB_PATH_TYPES:
        return Path(PurePath.as_posix(value)).expanduser()
    text, issues = runtime_text(
        value, field_name="startup_engine_scan_root", default=""
    )
    if issues or text == "":
        raise ValueError("startup_engine_scan_root_rejected")
    return Path(text).expanduser()


def detect_startup_engine_context(scan_root: object, max_files: int = 4000) -> dict[str, object]:
    scores = {'unity': 0.0, 'renpy': 0.0, 'rpgm': 0.0, 'media': 0.0, 'unknown': 1.0}
    evidence: tuple[Mapping[str, object], ...] = ()
    file_limit, limit_issues = runtime_int(
        max_files, field_name="startup_engine_max_files", default=4000
    )
    if limit_issues or file_limit < 1:
        evidence = limit_issues or (
            runtime_input_rejection(
                "startup_engine_max_files",
                max_files,
                "startup_engine_max_files_below_minimum",
            ),
        )
        return _empty_context(evidence)
    try:
        root = _startup_path(scan_root)
        paths: list[Path] = []
        if root.is_file():
            paths = [root]
        elif root.is_dir():
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = sorted(
                    name
                    for name in dirnames
                    if should_include_scan_path(Path(dirpath) / name, scan_root=root)
                )
                for filename in sorted(filenames):
                    paths.append(Path(dirpath) / filename)
                    if len(paths) >= file_limit:
                        break
                if len(paths) >= file_limit:
                    break
        else:
            return _empty_context()
        media_file_count = 0
        for path in paths:
            name = path.name.lower()
            suffix = path.suffix.lower()
            parts = {p.lower() for p in path.parts}
            if suffix in {'.png', '.jpg', '.jpeg', '.bmp', '.webp', '.gif', '.svg', '.mp3', '.wav', '.ogg', '.flac', '.m4a', '.mp4', '.webm', '.mkv', '.avi', '.mov'}:
                media_file_count += 1
                scores['media'] += 2.0
            else:
                has_magic, magic_evidence = _media_magic_result(path)
                if magic_evidence is not None:
                    evidence += (magic_evidence,)
                elif has_magic:
                    media_file_count += 1
                    scores['media'] += 2.0
            if suffix in {'.rpy', '.rpyc', '.rpa'} or 'renpy' in parts or 'renpy' in name:
                scores['renpy'] += 6.0
            if name in {'game.rgssad', 'game.rgss2a', 'game.rgss3a', 'rpg_core.js', 'rmmz_core.js', 'system.json', 'package.json'}:
                scores['rpgm'] += 6.0
            if suffix in {'.rpgmvp', '.rpgmvo', '.rpgmvm', '.rgssad', '.rgss2a', '.rgss3a'}:
                scores['rpgm'] += 6.0
            if name in {'unityplayer.dll', 'gameassembly.dll', 'globalgamemanagers', 'assembly-csharp.dll'}:
                scores['unity'] += 6.0
            if suffix in {'.assets', '.bundle', '.unity3d'}:
                scores['unity'] += 3.0
        if paths and media_file_count == len(paths) and not (scores['unity'] or scores['renpy'] or scores['rpgm']):
            scores['media'] += 4.0
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        return _empty_context(
            (
                runtime_input_rejection(
                    "startup_engine_scan_root",
                    scan_root,
                    _startup_reason("startup_engine_scan_unavailable", exc),
                ),
            )
        )
    return _normalize(scores, evidence)


def select_startup_profile_engine(context: dict[str, float], threshold: float = 0.8) -> str:
    context_state, context_issues = runtime_mapping(
        context, field_name="startup_engine_context"
    )
    limit, threshold_issues = runtime_float(
        threshold,
        field_name="startup_engine_threshold",
        default=0.8,
        minimum=0.0,
        maximum=1.0,
    )
    if context_issues or threshold_issues:
        raise ValueError("startup_engine_selection_input_rejected")
    known: dict[str, float] = {}
    for key in ('unity', 'renpy', 'rpgm', 'media'):
        score, issues = runtime_float(
            dict.get(context_state, key, 0.0),
            field_name=_startup_context_field(key),
            default=0.0,
            minimum=0.0,
        )
        if issues:
            raise ValueError("startup_engine_context_score_rejected")
        known[key] = score
    best = max(known, key=lambda key: known[key])
    return best if known[best] >= limit else 'other'


def resolve_startup_scan_engine_hint(scan_root: object, cli_engine: str = 'auto') -> tuple[str, dict[str, object]]:
    cli, cli_issues = runtime_text(
        cli_engine, field_name="startup_cli_engine", default="auto"
    )
    cli = cli.lower().strip()
    detected = detect_startup_engine_context(scan_root)
    if cli_issues:
        detected["input_evidence"] = tuple(
            detected.get("input_evidence", ())
        ) + cli_issues
    detected_best = select_startup_profile_engine(detected)
    if detected_best in {'unity', 'renpy', 'rpgm', 'media'} and detected[detected_best] >= PLR2004N0_8:
        return detected_best, detected
    if cli in {'unity', 'renpy', 'rpgm', 'media'}:
        return cli, _engine_hint_to_context(cli)
    if cli == 'other':
        return 'other', _engine_hint_to_context('unknown')
    return detected_best, detected


__all__ = ('detect_startup_engine_context', 'resolve_startup_scan_engine_hint', 'select_startup_profile_engine')
