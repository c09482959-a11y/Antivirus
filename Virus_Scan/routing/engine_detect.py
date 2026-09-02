from types import MappingProxyType
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from pathlib import Path, PurePath
from Virus_Scan.runtime.api import (
    get_init_value,
    get_profiles_dir,
    log_error,
    path_runtime_owner,
    program_root,
    record_detector_error,
    runtime_value,
    profile_scoring_state,
)
from Virus_Scan.contracts.artifact_read_snapshot import read_artifact_prefix
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.utils.stages import normalize_profile_extension
from Virus_Scan.utils.tagging import normalize_tags
from Virus_Scan.utils.probability import safe_clamp
from Virus_Scan.core.jsonio import deepcopy_jsonable
from Virus_Scan.routing.engine_target_detection import detect_target_engine_context_from_layout
from Virus_Scan.routing.profile_model_projection import (
    ProfileSchemaInvariantError,
    load_routing_engine_profile,
)

PLR2004N0_35 = 0.35
PLR2004N0_8 = 0.8

ENGINE_FILE_CONTEXT_CUES = MappingProxyType(dict(runtime_value('ENGINE_FILE_CONTEXT_CUES', {})))
GAME_ENGINE_ADMIN_IMPOSSIBLE_TAGS = frozenset(runtime_value('GAME_ENGINE_ADMIN_IMPOSSIBLE_TAGS', ()))
GAME_ENGINE_CONTEXT_TAGS = frozenset(runtime_value(
    'GAME_ENGINE_CONTEXT_TAGS',
    (
        'renpy', 'renpy_script', 'renpy_bytecode', 'unity', 'unity_asset',
        'rpgm', 'rpgm_js', 'nwjs', 'actual_stage_asset',
        'actual_stage_script', 'router_stage_asset', 'router_stage_script',
    ),
))
ENGINE_BASELINE_CONFIDENCE_THRESHOLD = float(runtime_value('ENGINE_BASELINE_CONFIDENCE_THRESHOLD', 0.65))
QUALITY_GATE_VERSION = int(runtime_value('QUALITY_GATE_VERSION', 1))
ENGINE_PROFILES = runtime_value('ENGINE_PROFILES', {})

MEDIA_PROFILE_EXTENSIONS = frozenset({'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tif', '.tiff', '.ico', '.dds', '.ktx', '.ktx2', '.pvr', '.qoi', '.tga', '.mp3', '.wav', '.ogg', '.oga', '.opus', '.flac', '.mp4', '.m4v', '.m4a', '.mov', '.avi', '.webm', '.mkv'})
MEDIA_PROFILE_TAGS = frozenset({
    'media_asset', 'image_asset', 'audio_asset', 'video_asset',
    'image_file', 'audio_file', 'video_file', 'filetype_image', 'filetype_audio', 'filetype_video',
    'magic_png', 'magic_jpeg', 'magic_gif', 'magic_webp', 'magic_ogg', 'magic_mp3', 'magic_flac', 'magic_mp4',
    'stego_payload_suspect', 'embedded_payload_after_eof',
})
_ENGINE_CONTEXT_KEYS = ('unity', 'renpy', 'rpgm', 'media', 'unknown')


def _engine_text(value: object, *, default: object='') -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='routing_engine_text_missing',
        unsupported_reason='routing_engine_text_rejected',
    )
    return str.__str__(text) if reason == '' else default


def _engine_lower_text(value: object, *, default: object='') -> object:
    return _engine_text(value, default=default).strip().lower()


def _engine_path_text(value: object) -> object:
    if isinstance(value, PurePath):
        return PurePath.__str__(value)
    return _engine_text(value)


def _engine_mapping_snapshot(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return {}
    out = {}
    for index, (key, item) in enumerate(items):
        text, reason = no_hook_text(
            key,
            missing_reason='routing_engine_key_missing',
            unsupported_reason='routing_engine_key_rejected',
        )
        if reason or text == '':
            text = str.__add__('routing_engine_key_', int.__str__(index))
        out[text] = item
    return out


def _engine_sequence_texts(value: object) -> object:
    out = []
    for item in no_hook_sequence_items(value):
        text = _engine_lower_text(item)
        if text:
            out.append(text)
    return tuple(out)


def _engine_score(value: object, *, default: object=0.0) -> object:
    metric, reason = no_hook_finite_float(
        value,
        default=default,
        minimum=0.0,
        maximum=1.0,
        reason='routing_engine_score_rejected',
        non_finite_reason='routing_engine_score_non_finite',
    )
    return default if reason else metric


def _routing_prior_unavailable_score(reason: str) -> float:
    # Explicit degraded-probe score for prior lookups whose backing profile is unavailable.
    # The caller records the concrete exception before using this neutral score.
    del reason  # Explicitly unused contract parameters.
    return _engine_score(0.0, default=0.0)


def _engine_float(value: object, *, default: object=0.0) -> object:
    metric, reason = no_hook_finite_float(
        value,
        default=default,
        reason='routing_engine_number_rejected',
        non_finite_reason='routing_engine_number_non_finite',
    )
    return default if reason else metric


def _engine_int(value: object, *, default: object=0) -> object:
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        default=default,
        reason='routing_engine_integer_rejected',
        non_finite_reason='routing_engine_integer_non_finite',
    )
    return default if reason else parsed


def _engine_hint_to_context(engine: object) -> object:
    engine_text = _engine_lower_text(engine, default='unknown')
    if engine_text == 'other':
        engine_text = 'unknown'
    context = dict.fromkeys(_ENGINE_CONTEXT_KEYS, 0.0)
    context[engine_text if engine_text in context else 'unknown'] = 1.0
    return context


def _owned_context_message(context: object, exc: object) -> object:
    context_text = _engine_text(context, default='routing_engine')
    return str.__add__(str.__add__(context_text, ': '), no_hook_type_name(exc))


def _profile_runtime_values() -> object:
    engines = tuple(get_init_value('DEFAULT_ENGINES') or ('renpy', 'rpgm', 'unity', 'media', 'other'))
    profiles_dir = get_profiles_dir(None) or get_init_value('PROFILES_DIR')
    if not profiles_dir:
        base_dir = get_init_value('BASE_DIR') or str(program_root())
        profiles_dir = str(Path(base_dir, 'profiles'))
    profile_lock = get_init_value('PROFILE_FILE_LOCK')
    engine_cache = get_init_value('ENGINE_CACHE') or {}
    profile_ext_locks = get_init_value('PROFILE_EXT_LOCKS')
    return engines, profiles_dir, profile_lock, engine_cache, profile_ext_locks

def _cluster_engine_prefix(engine_context: object=None, node: object=None) -> object:
    try:
        ctx = _engine_mapping_snapshot(engine_context)
        scored_ctx = {key: _engine_score(value) for key, value in dict.items(ctx)}
        engine = max(dict.items(scored_ctx), key=lambda item: item[1])[0] if scored_ctx else 'unknown'
        if engine == 'other':
            engine = 'unknown'
        if engine not in ('unity', 'renpy', 'rpgm', 'media', 'unknown'):
            engine = 'unknown'
        ext = normalize_profile_extension('' if node is None else node)
        if not ext or ext == '<no_ext>':
            ext = 'noext'
        ext = ext.replace('.', '').replace('<', '').replace('>', '') or 'noext'
        return ''.join((engine, '_', ext, '_cluster_'))
    except RECOVERABLE_RUNTIME_ERRORS:
        return 'unknown_noext_cluster_'

def _game_engine_context(report_set: object) -> bool:
    normalized = normalize_tags(report_set)
    tagset = frozenset(tag.lower() for tag in normalized if type(tag) is str)
    return bool(tagset & GAME_ENGINE_CONTEXT_TAGS)

def _game_engine_admin_impossible_context(evidence: object, report_set: object) -> object:
    """Game engines should not perform IT-admin persistence/credential tasks."""
    if not _game_engine_context(report_set):
        return (False, '')
    hits = sorted(set(evidence or []) & GAME_ENGINE_ADMIN_IMPOSSIBLE_TAGS)
    if hits:
        return (True, 'game_engine_impossible_admin_behavior:' + ','.join(hits[:8]))
    return (False, '')

def _profile_ext_lock(engine: object, ext: object) -> object:
    _, _, _, _, profile_ext_locks = _profile_runtime_values()
    if profile_ext_locks is None:
        exception_message = 'profile extension locks not initialized'
        raise RuntimeError(exception_message)
    engine_text = _engine_lower_text(engine, default='other')
    if engine_text not in {'renpy', 'rpgm', 'unity', 'media', 'other'}:
        engine_text = 'other'
    ext_text = normalize_profile_extension('' if ext is None else ext)
    return profile_ext_locks[engine_text, ext_text]

def _engine_detect_log_recoverable(context: object, exc: object) -> object:
    try:
        log_error(_owned_context_message(context, exc))
    except RECOVERABLE_RUNTIME_ERRORS:
        try:
            return record_detector_error(
                _engine_text(context, default='routing_engine'),
                exc,
                context={'routing_engine_log_unavailable': no_hook_type_name(exc)},
            )
        except RECOVERABLE_RUNTIME_ERRORS:
            return {
                'detector': _engine_text(context, default='routing_engine'),
                'error': no_hook_type_name(exc),
                'context': {'routing_engine_log_unavailable': True},
            }
    return True
def engine_confidence_report(engine_context: object=None, path: object=None, tags: object=None, strings_blob: object='') -> object:
    """Explain active engine selection and whether engine/ext baseline suppression is trusted."""
    ctx = _engine_mapping_snapshot(engine_context)
    try:
        active = select_active_profile_engine(ctx)
    except RECOVERABLE_RUNTIME_ERRORS:
        active = 'other'
    engines, _, _, _, _ = _profile_runtime_values()
    if active not in engines:
        active = 'other'
    confidence = _engine_score(dict.get(ctx, active, 0.0))
    tagset = set(_engine_sequence_texts(tags))
    text = _engine_lower_text(strings_blob)
    reasons = []
    path_l = _engine_lower_text(path)
    if active == 'renpy' and (tagset & {'renpy', 'renpy_bytecode', 'renpy_script'} or any((x in path_l for x in ('renpy', '.rpy', '.rpa')))):
        reasons.append('renpy file/tag/path cues')
    if active == 'unity' and (tagset & {'unity', 'unity_managed_code'} or any((x in text or x in path_l for x in ('unityplayer', 'gameassembly', 'assembly-csharp')))):
        reasons.append('unity runtime/assembly cues')
    if active == 'rpgm' and (tagset & {'rpgm', 'rpgm_node_runtime'} or any((x in path_l for x in ('www/data', '.rvdata', '.rgss')))):
        reasons.append('rpgm file/path cues')
    if active == 'media' and (tagset & {'media_asset', 'image_asset', 'audio_asset', 'video_asset'} or any((x in path_l for x in ('.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp3', '.wav', '.ogg', '.mp4', '.webm', '.mkv')))):
        reasons.append('media file/tag/path cues')
    if active == 'other':
        reasons.append('no confident specific engine; using generic profile')
    allow = active == 'other' or confidence >= ENGINE_BASELINE_CONFIDENCE_THRESHOLD
    return {'version': QUALITY_GATE_VERSION, 'active_profile': active, 'confidence': max(0.0, min(1.0, confidence)), 'baseline_suppression_allowed': allow, 'threshold': ENGINE_BASELINE_CONFIDENCE_THRESHOLD, 'reasons': reasons[:20], 'raw_context': {key: _engine_score(value) for key, value in dict.items(ctx)}}

def engine_extension_key(engine: object, file_path: object) -> object:
    engines, _, _, _, _ = _profile_runtime_values()
    engine_text = _engine_lower_text(engine, default='other')
    engine_text = engine_text if engine_text in engines else 'other'
    return str.__add__(str.__add__(engine_text, ':'), normalize_profile_extension(file_path))

def freeze_profile_scoring_snapshot() -> object:
    scoring_state = profile_scoring_state()
    engines, _, profile_lock, _, _ = _profile_runtime_values()
    with profile_lock:
        loaded_profiles = {}
        for engine in engines:
            engine_text = _engine_lower_text(engine, default='other')
            try:
                loaded_profiles[engine_text] = load_routing_engine_profile(engine_text)
            except ProfileSchemaInvariantError:
                raise
            except RECOVERABLE_RUNTIME_ERRORS as e:
                log_error('profile snapshot load failed for ' + engine_text + ': ' + no_hook_type_name(e))
        missing = [_engine_lower_text(engine, default='other') for engine in engines if _engine_lower_text(engine, default='other') not in loaded_profiles]
        if missing:
            exception_message = 'profile scoring snapshot missing engines'
            raise ProfileSchemaInvariantError(exception_message)
        return scoring_state.freeze(deepcopy_jsonable(loaded_profiles))

def get_scoring_profile(engine: object) -> object:
    engines, _, _, _, _ = _profile_runtime_values()
    engine = _engine_lower_text(engine, default='other')
    engine = engine if engine in engines else 'other'
    scoring_state = profile_scoring_state()
    if scoring_state.is_frozen():
        snap = scoring_state.get_profile(engine)
        if isinstance(snap, dict):
            return snap
        exception_message = 'missing frozen scoring profile'
        raise ProfileSchemaInvariantError(exception_message)
    return load_routing_engine_profile(engine)

def infer_engine_context(tags: object, file_structure: object=None, strings_blob: object='') -> object:
    """
    Produces probabilistic engine context, not a malware verdict.

    Reliability fix:
    - use file extension/path/name cues for engine-native files;
    - keep generic .exe/.dll ambiguous unless a scan-level or string cue exists;
    - let concrete per-file cues supersede the runtime hint.
    """
    scores = {'unity': 0.0, 'renpy': 0.0, 'rpgm': 0.0, 'media': 0.0, 'unknown': 0.1}
    tags_l = set(_engine_sequence_texts(tags))
    blob_l = _engine_lower_text(strings_blob)
    path_l = _engine_lower_text(file_structure).replace('\\', '/')
    try:
        ext_l = Path(path_l).suffix.lower()
    except RECOVERABLE_RUNTIME_ERRORS:
        ext_l = ''
    for engine, cues in no_hook_mapping_items(ENGINE_FILE_CONTEXT_CUES) or ():
        cue_items = dict(no_hook_mapping_items(cues) or ())
        extensions = no_hook_sequence_items(dict.get(cue_items, 'extensions', ()))
        path_markers = no_hook_sequence_items(dict.get(cue_items, 'path_markers', ()))
        string_markers = no_hook_sequence_items(dict.get(cue_items, 'string_markers', ()))
        tag_markers = set(_engine_sequence_texts(dict.get(cue_items, 'tag_markers', ())))
        if ext_l and ext_l in extensions:
            scores[engine] += 4.0
        if any((marker in path_l for marker in path_markers if type(marker) is str)):
            scores[engine] += 3.0
        if any((marker in blob_l for marker in string_markers if type(marker) is str)):
            scores[engine] += 3.5
        if tags_l & tag_markers:
            scores[engine] += 2.5
    if ext_l in MEDIA_PROFILE_EXTENSIONS:
        scores['media'] += 4.0
    if tags_l & MEDIA_PROFILE_TAGS:
        scores['media'] += 2.5
    if 'assets' in path_l and ext_l not in {'.rpa', '.rvdata', '.rvdata2', '.rxdata'}:
        scores['unity'] += 0.75
    if 'game/scripts' in path_l:
        scores['renpy'] += 2.0
    if 'www/data' in path_l or 'www/js' in path_l:
        scores['rpgm'] += 2.0
    total = sum(dict.values(scores)) + 1e-06
    scores = {k: safe_clamp(v / total, 0.0, 1.0) for k, v in dict.items(scores)}
    return merge_engine_context_with_runtime_hint(scores)

def infer_profile_engine(tags: object, file_structure: object=None, strings_blob: object='') -> object:
    """
    Chooses which engine-scoped authoritative profile to use.

    The engine is only the container.
    Extension baseline still controls learning.
    """
    try:
        engine_ctx = infer_engine_context(
            () if tags is None else tags,
            file_structure=file_structure,
            strings_blob='' if strings_blob is None else strings_blob,
        )
        if not engine_ctx:
            return ('other', {'other': 1.0})
        engine = select_active_profile_engine(engine_ctx)
        engines, _, _, _, _ = _profile_runtime_values()
        if engine not in engines:
            engine = 'other'
        return (engine, engine_ctx)
    except RECOVERABLE_RUNTIME_ERRORS as e:
        log_error('profile engine inference failed: ' + no_hook_type_name(e))
        return ('other', {'other': 1.0})

def is_unity_context_for_file(path: object, tags: object=None, strings_blob: object='') -> object:
    """True only when this specific file is in Unity context."""
    try:
        ctx = infer_engine_context(() if tags is None else tags, file_structure=path, strings_blob='' if strings_blob is None else strings_blob)
        active = select_active_profile_engine(ctx)
        return (active == 'unity', ctx)
    except RECOVERABLE_RUNTIME_ERRORS:
        return (False, {})

def json_cluster_prior(tags: object, engine: object) -> object:
    try:
        engine = _engine_lower_text(engine, default='other')
        engine = engine if engine in ('renpy', 'unity', 'rpgm') else 'other'
        profile = load_routing_engine_profile(engine)
        profile_items = dict(no_hook_mapping_items(profile) or ())
        stats = dict(no_hook_mapping_items(dict.get(profile_items, 'tags', {})) or ())
        total = _engine_float(dict.get(profile_items, 'total', 1.0), default=1.0) + 1e-06
        score = 0.0
        tag_items = _engine_sequence_texts(tags)
        for t in tag_items:
            freq = _engine_float(dict.get(stats, t, 0.0))
            score += 1.0 - freq / total
        if len(tag_items) == 0:
            return 0.0
        return safe_clamp(score / (len(tag_items) + 1e-06))
    except RECOVERABLE_RUNTIME_ERRORS as e:
        record_detector_error('json_cluster_prior', e, context={'routing_json_prior_unavailable': no_hook_type_name(e)})
        return _routing_prior_unavailable_score('json_cluster_prior_unavailable')

def merge_engine_context_with_runtime_hint(engine_context: object) -> object:
    """
    Merge target-level engine detection without hiding per-file evidence.

    If a file has strong concrete engine cues, the hint remains weak. If the file
    is ambiguous (common for a Unity/RPGM game .exe or .dll), a confidently
    detected scan-level engine becomes the active profile context instead of
    falling back to the canonical other profile.
    """
    ctx = _engine_mapping_snapshot(engine_context)
    snapshot = path_runtime_owner().snapshot()
    hint_ctx = _engine_mapping_snapshot(snapshot.scan_engine_hint_context)
    hint = _engine_lower_text(snapshot.scan_engine_hint, default='auto')
    if hint in {'unity', 'renpy', 'rpgm', 'media'}:
        known_keys = ('unity', 'renpy', 'rpgm', 'media')
        known_max = max((_engine_score(dict.get(ctx, k, 0.0)) for k in known_keys))
        hint_conf = _engine_score(dict.get(hint_ctx, hint, 0.0))
        ambiguous_file = known_max < PLR2004N0_35 and hint_conf >= PLR2004N0_8
        weight = 2.25 if ambiguous_file else 0.2
        if ambiguous_file:
            ctx['unknown'] = _engine_score(dict.get(ctx, 'unknown', 0.0)) * 0.1
        for k in ('unity', 'renpy', 'rpgm', 'media', 'unknown'):
            ctx[k] = _engine_score(dict.get(ctx, k, 0.0)) + weight * _engine_score(dict.get(hint_ctx, k, 0.0))
        total = sum((_engine_float(v) for v in dict.values(ctx))) + 1e-06
        ctx = {k: safe_clamp(_engine_float(v) / total, 0.0, 1.0) for k, v in dict.items(ctx)}
    return ctx

def _engine_detect_clamp(x: object, lo: object=0.0, hi: object=1.0) -> object:
    v = _engine_float(x)
    lower = _engine_float(lo)
    upper = _engine_float(hi, default=1.0)
    return max(lower, min(upper, v))

def _engine_detect_rel(path: object, root: object) -> object:
    try:
        return Path(path).relative_to(Path(root)).as_posix().lower()
    except RECOVERABLE_RUNTIME_ERRORS:
        return _engine_lower_text(path).replace('\\', '/')

def _engine_read_prefix(path: object, max_bytes: object=65536) -> object:
    limit = _engine_int(max_bytes, default=65536)
    try:
        path_text = _engine_path_text(path)
        if path_text == '':
            return b''
        return read_artifact_prefix(path_text, limit)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _engine_detect_log_recoverable('engine prefix read unavailable', exc)
        return b''

def detect_target_engine_context(scan_root: object, max_files: object=600) -> object:
    """Fast scan-root engine detection through bounded routing-owned layout helpers."""
    return detect_target_engine_context_from_layout(
        scan_root,
        max_files=_engine_int(max_files, default=600),
        rel_fn=_engine_detect_rel,
        read_prefix=_engine_read_prefix,
        log_recoverable=_engine_detect_log_recoverable,
        clamp=_engine_detect_clamp,
    )

def resolve_scan_engine_hint(scan_root: object, cli_engine: object='auto') -> object:
    """
    CLI engine is the configured baseline. Startup detection can supersede it when confident.
    """
    cli_engine = _engine_lower_text(cli_engine, default='auto').strip()
    detected = detect_target_engine_context(scan_root)
    detected_best = select_active_profile_engine(detected)
    detected_conf = _engine_score(dict.get(detected, detected_best, 0.0)) if detected_best in detected else 0.0
    if detected_best in {'unity', 'renpy', 'rpgm', 'media'} and detected_conf >= PLR2004N0_8:
        return (detected_best, detected)
    if cli_engine in {'unity', 'renpy', 'rpgm', 'media', 'other'}:
        return (cli_engine, _engine_hint_to_context(cli_engine))
    return (detected_best, detected)

def sanitize_profile_context(engine_context: object=None, threshold: object=0.8) -> object:
    ctx = _engine_mapping_snapshot(engine_context)
    active = select_active_profile_engine(ctx, threshold=threshold)
    return {'active_profile': active, 'profile_selection_mode': 'exclusive_canonical_engine_else_other', 'profile_selection_threshold': _engine_score(threshold, default=0.8), 'raw_engine_context': {key: _engine_score(value) for key, value in dict.items(ctx)}, 'other_profile_enabled': active == 'other'}

def select_active_profile_engine(engine_context: object=None, threshold: object=0.8) -> object:
    """
    Choose exactly one canonical engine profile for scoring/learning.

    The other profile is the unknown-engine baseline, not a blendable profile. Known engines
    win when their confidence is high enough; otherwise other is used
    exclusively. This prevents generic other-profile statistics from leaking into
    Ren'Py/Unity/RPGM game profiles while preserving anchors, clustering,
    Markov, graph output, and adaptive weighting.
    """
    ctx = _engine_mapping_snapshot(engine_context)
    known = {}
    for k in ('renpy', 'unity', 'rpgm', 'media'):
        known[k] = _engine_score(dict.get(ctx, k, 0.0))
    best_engine = max(tuple(dict.keys(known)), key=lambda key: dict.get(known, key, 0.0))
    if dict.get(known, best_engine, 0.0) >= _engine_score(threshold, default=0.8):
        return best_engine
    return 'other'

def update_engine_profile(engine: object, ext: object, tags: object, risk: object) -> None:
    profile = ENGINE_PROFILES[engine]
    profile['files'] += 1
    profile['risk_sum'] += risk
    profile['avg_risk'] = profile['risk_sum'] / max(1, profile['files'])
    profile['extensions'][ext] += 1
    for t in tags:
        profile['tags'][t] += 1
