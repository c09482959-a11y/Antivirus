"""Bounded target-level engine detection helpers.

This module is routing-owned: it inspects target layout and small content
prefixes to infer the game-engine context used by routing/profile selection.
It does not perform scanning, scoring, publication, or JSON mutation.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path, PurePath
from typing import Callable, Iterable, Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_text,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.path_identity import should_include_scan_path

from Virus_Scan.routing.engine_target_policy import (INITIAL_SCORES, PRIORITY_BASENAMES, PRIORITY_EXTENSIONS, RENPY_EXTENSIONS, RGSS_EXTENSIONS, RPGM_CORE_FILES, RPGM_DATA_FILES, RPGM_ENCRYPTED_EXTENSIONS, RPGM_RUNTIME_FILES, UNITY_CODE_FILES)


PLR2004N15_0 = 15.0
PLR2004N4_0 = 4.0

RelFn = Callable[[Path, Path], str]
LogFn = Callable[[str, BaseException], object]
ReadPrefixFn = Callable[[Path, int], bytes]
ClampFn = Callable[[float, float, float], float]


def _target_text(value: object, *, default: str = "") -> str:
    if isinstance(value, PurePath):
        return PurePath.__str__(value)
    text, reason = no_hook_text(
        value,
        missing_reason="target_engine_text_missing",
        unsupported_reason="target_engine_text_rejected",
    )
    return default if reason else text


def _target_float(value: object, *, default: float = 0.0) -> float:
    metric, reason = no_hook_finite_float(
        value,
        default=default,
        reason="target_engine_float_rejected",
        non_finite_reason="target_engine_float_rejected",
    )
    return default if reason else metric


def _target_int(value: object, *, default: int = 600) -> int:
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        default=default,
        reason="target_engine_int_rejected",
        non_finite_reason="target_engine_int_rejected",
    )
    return default if reason else parsed


def _target_path(value: object) -> Path | None:
    text = _target_text(value)
    path_value: Path | None = None
    if text != "":
        try:
            path_value = Path(text)
        except RECOVERABLE_RUNTIME_ERRORS:
            path_value = None
    return path_value


def _float_mapping_items(value: Mapping[str, float]) -> tuple[tuple[str, float], ...]:
    items = no_hook_mapping_items(value)
    if items is None:
        return ()
    out: list[tuple[str, float]] = []
    for key, metric in items:
        key_text = _target_text(key)
        if key_text:
            out.append((key_text, _target_float(metric)))
    return tuple(out)


def _initial_scores() -> dict[str, float]:
    return dict(_float_mapping_items(INITIAL_SCORES))


def _zip_member_dirs(member_name: str) -> Iterable[str]:
    parent = member_name.rsplit('/', 1)[0] if '/' in member_name else ''
    while parent:
        yield parent
        if '/' not in parent:
            break
        parent = parent.rsplit('/', 1)[0]


def _collect_zip_layout(root: Path, rels: list[str], dirs: set[str], log_recoverable: LogFn) -> None:
    try:
        if not zipfile.is_zipfile(str(root)):
            return
        with zipfile.ZipFile(str(root)) as zf:
            for info in zf.infolist()[:10000]:
                name = _target_text(info.filename).lower().replace('\\', '/').strip('/')
                if not name:
                    continue
                if name.endswith('/'):
                    dirs.add(name.strip('/'))
                    continue
                rels.append(name)
                dirs.update(_zip_member_dirs(name))
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_recoverable('target engine archive-name inspection failed', exc)


def _collect_file_layout(root: Path, rel_fn: RelFn, log_recoverable: LogFn) -> tuple[list[Path], list[str], set[str]]:
    files = [root]
    rels = [rel_fn(root, root.parent)]
    dirs = {''}
    _collect_zip_layout(root, rels, dirs, log_recoverable)
    return files, rels, dirs


def _collect_dir_layout(root: Path, max_files: int, rel_fn: RelFn) -> tuple[list[Path], list[str], set[str]]:
    files: list[Path] = []
    rels: list[str] = []
    dirs: set[str] = set()
    for cur, dirnames, filenames in os.walk(str(root)):
        curp = Path(cur)
        dirnames[:] = sorted(
            (
                name
                for name in dirnames
                if should_include_scan_path(curp / name, scan_root=root)
            ),
            key=lambda item: item.casefold(),
        )
        rel_dir = rel_fn(curp, root).strip('/')
        if rel_dir and rel_dir != '.':
            dirs.add(rel_dir)
        for name in sorted(filenames, key=lambda item: item.casefold()):
            candidate = curp / name
            if not should_include_scan_path(candidate, scan_root=root):
                continue
            rel_path = (rel_dir + '/' + name).strip('/').lower().replace('\\', '/')
            rels.append(rel_path)
            if len(files) < _target_int(max_files, default=600):
                files.append(candidate)
    return files, rels, dirs


def _collect_target_layout(
    scan_root: object,
    max_files: int,
    rel_fn: RelFn,
    log_recoverable: LogFn,
) -> tuple[list[Path], list[str], set[str]]:
    root = _target_path(scan_root)
    if root is None:
        return [], [], set()
    if root.is_file():
        return _collect_file_layout(root, rel_fn, log_recoverable)
    if root.is_dir():
        return _collect_dir_layout(root, max_files, rel_fn)
    return [], [], set()


def _score_rpgm_layout(scores: dict[str, float], rels: list[str], dirs: set[str]) -> dict[str, bool]:
    dir_joined = '\n'.join(sorted(dirs)[:5000])
    has_www_data = 'www/data' in dir_joined or any(r.startswith('www/data/') for r in rels)
    has_www_js = 'www/js' in dir_joined or any(r.startswith('www/js/') for r in rels)
    has_rpgm_core = any(r.endswith(RPGM_CORE_FILES) for r in rels)
    has_rpgm_data = any(r.endswith(RPGM_DATA_FILES) for r in rels)
    has_rpgm_nw_runtime = any(r.endswith(RPGM_RUNTIME_FILES) for r in rels)
    has_rpgm_encrypted_asset_name = any(r.endswith(RPGM_ENCRYPTED_EXTENSIONS) for r in rels)
    has_rgss = any(r.endswith(RGSS_EXTENSIONS) or 'game.rgss' in r for r in rels)
    if has_www_data and has_www_js:
        scores['rpgm'] += 10.0
    if has_rpgm_core:
        scores['rpgm'] += 8.0
    if has_rpgm_data:
        scores['rpgm'] += 5.0
    if has_rpgm_nw_runtime and (has_www_data or has_www_js or has_rpgm_core or has_rpgm_data):
        scores['rpgm'] += 7.0
    elif has_rpgm_nw_runtime and has_rpgm_encrypted_asset_name:
        scores['rpgm'] += 5.0
    if has_rpgm_encrypted_asset_name and (has_www_data or has_www_js or has_rpgm_core or has_rpgm_data):
        scores['rpgm'] += 5.0
    elif has_rpgm_encrypted_asset_name:
        scores['rpgm'] += 4.0
    if has_rgss:
        scores['rpgm'] += 8.0
    return {
        'www_data_and_js': has_www_data and has_www_js,
        'core': has_rpgm_core,
        'encrypted_asset': has_rpgm_encrypted_asset_name,
        'rgss': has_rgss,
    }


def _score_unity_layout(scores: dict[str, float], rels: list[str], dirs: set[str]) -> dict[str, bool]:
    has_unity_player = any(
        r.endswith(('unityplayer.dll', 'unityplayer.so', 'unityplayer.dylib'))
        for r in rels
    )
    has_unity_data_dir = any(r.endswith('_data') or '/managed' in r or 'il2cpp_data' in r for r in dirs)
    has_unity_global = any('globalgamemanagers' in r or r.endswith('resources.assets') or '.assets.resS'.lower() in r.lower() for r in rels)
    has_unity_code = any(r.endswith(UNITY_CODE_FILES) for r in rels)
    if has_unity_player:
        scores['unity'] += 9.0
    if has_unity_data_dir and (has_unity_global or has_unity_code or has_unity_player):
        scores['unity'] += 8.0
    if has_unity_global:
        scores['unity'] += 5.0
    if has_unity_code:
        scores['unity'] += 5.0
    return {'player': has_unity_player, 'global': has_unity_global, 'code': has_unity_code}


def _score_renpy_layout(scores: dict[str, float], rels: list[str], dirs: set[str]) -> dict[str, bool]:
    has_renpy_dir = any(d in {'renpy', 'game'} or d.endswith(('/renpy', '/game')) for d in dirs)
    has_renpy_files = any(r.endswith(RENPY_EXTENSIONS) for r in rels)
    has_renpy_runtime = any('librenpython' in r or r.endswith('renpy.exe') for r in rels)
    if has_renpy_files:
        scores['renpy'] += 9.0
    if has_renpy_dir and has_renpy_files:
        scores['renpy'] += 6.0
    if has_renpy_runtime:
        scores['renpy'] += 6.0
    return {'files': has_renpy_files, 'runtime': has_renpy_runtime}


def _priority_file_pairs(files: list[Path], rels: list[str]) -> list[tuple[Path, str]]:
    pairs = []
    for file_path, rel_path in zip(files, rels, strict=False):
        name = rel_path.rsplit('/', 1)[-1]
        if name in PRIORITY_BASENAMES or rel_path.endswith(PRIORITY_EXTENSIONS):
            pairs.append((file_path, rel_path))
    return pairs


def _score_priority_content(scores: dict[str, float], files: list[Path], rels: list[str], read_prefix: ReadPrefixFn) -> None:
    for path, rel_path in _priority_file_pairs(files, rels)[:80]:
        data = read_prefix(path, 128000)
        if not data:
            continue
        blob = data.decode('latin1', errors='ignore').lower()
        if data.startswith((b'RPGMV', b'RPGMZ')):
            scores['rpgm'] += 4.0
        if rel_path.endswith(('rpg_core.js', 'rmmz_core.js', 'package.json', 'system.json')) and any(
            marker in blob for marker in ('rpg maker', 'rmmv', 'rmmz', 'rpggame', 'nw.js')
        ):
            scores['rpgm'] += 4.0
        if rel_path.endswith(('globalgamemanagers', 'unityplayer.dll', 'gameassembly.dll', 'assembly-csharp.dll')) and any(
            marker in blob for marker in ('unity', 'il2cpp', 'monobehaviour', 'assembly-csharp')
        ):
            scores['unity'] += 3.0
        if rel_path.endswith(('.rpy', '.rpyc')) and any(marker in blob for marker in ('renpy', "ren'py")):
            scores['renpy'] += 3.0


def _dampen_conflicting_scores(
    scores: dict[str, float],
    rpgm_flags: dict[str, bool],
    unity_flags: dict[str, bool],
    renpy_flags: dict[str, bool],
) -> None:
    has_unity = bool(unity_flags.get('player') or unity_flags.get('global') or unity_flags.get('code'))
    has_rpgm = bool(rpgm_flags.get('www_data_and_js') or rpgm_flags.get('core') or rpgm_flags.get('rgss') or rpgm_flags.get('encrypted_asset'))
    has_renpy = bool(renpy_flags.get('files') or renpy_flags.get('runtime'))
    if scores['rpgm'] >= PLR2004N15_0 and not has_unity:
        scores['unity'] *= 0.25
    if scores['rpgm'] >= PLR2004N4_0 and rpgm_flags.get('encrypted_asset') and not (has_unity or has_renpy):
        scores['unknown'] *= 0.25
    if scores['unity'] >= PLR2004N15_0 and not has_rpgm:
        scores['rpgm'] *= 0.5


def _normalize_engine_scores(scores: dict[str, float], clamp: ClampFn) -> dict[str, float]:
    score_items = _float_mapping_items(scores)
    total = sum(value for _key, value in score_items) + 1e-06
    return {key: clamp(value / total, 0.0, 1.0) for key, value in score_items}


def detect_target_engine_context_from_layout(
    scan_root: object,
    max_files: int,
    rel_fn: RelFn,
    read_prefix: ReadPrefixFn,
    log_recoverable: LogFn,
    clamp: ClampFn,
) -> dict[str, float]:
    """Infer target-level engine probabilities from layout and bounded content prefixes."""
    scores = _initial_scores()
    try:
        files, rels, dirs = _collect_target_layout(scan_root, max_files, rel_fn, log_recoverable)
        limited_rels = rels[:5000]
        rpgm_flags = _score_rpgm_layout(scores, limited_rels, dirs)
        unity_flags = _score_unity_layout(scores, limited_rels, dirs)
        renpy_flags = _score_renpy_layout(scores, limited_rels, dirs)
        _score_priority_content(scores, files, rels, read_prefix)
        _dampen_conflicting_scores(scores, rpgm_flags, unity_flags, renpy_flags)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_recoverable('target engine detection failed', exc)
    return _normalize_engine_scores(scores, clamp)
