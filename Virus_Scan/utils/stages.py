"""Direct-import-safe stage and extension classification helpers."""
from __future__ import annotations

from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.utils.text_validation import text_boundary_value
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.contracts.path_identity import get_scan_extension as _contract_get_scan_extension
from typing import Mapping
from types import MappingProxyType
from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_mapping_items

PLR2004N0_55 = 0.55
PLR2004N0_85 = 0.85

MEDIA_AUDIO_EXTENSIONS = frozenset({'.ogg','.oga','.opus','.mp3','.wav','.flac','.m4a','.aac','.wma'})
MEDIA_VIDEO_EXTENSIONS = frozenset({'.mp4','.webm','.avi','.mov','.mkv','.wmv'})
IMAGE_EXTENSIONS = frozenset({'.png','.jpg','.jpeg','.bmp','.webp','.gif'})
FONT_ASSET_EXTENSIONS = frozenset({'.ttf','.otf','.fnt','.woff','.woff2'})
UNITY_CONTAINER_ASSET_EXTENSIONS = frozenset({'.assets','.asset','.bundle','.unity3d','.resource','.resources','.ress'})
MEDIA_ASSET_EXTENSIONS = MEDIA_AUDIO_EXTENSIONS | MEDIA_VIDEO_EXTENSIONS | IMAGE_EXTENSIONS
CLAIM_CATEGORY_STAGE: Mapping[str, str] = MappingProxyType({
    'binary': 'binary', 'archive': 'archive', 'image': 'image', 'asset': 'asset',
    'runtime': 'runtime', 'script': 'runtime', 'text': 'asset', 'font': 'asset',
})


def _stage_text(value: object, *, default: str = '') -> str:
    text = text_boundary_value(value, unsupported=None)
    if type(text) is not str:
        return default
    return str.__str__(text)


def _stage_lower_text(value: object, *, default: str = '') -> str:
    return _stage_text(value, default=default).strip().lower()


def _stage_owned_items(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if type(value) in (tuple, list, set, frozenset):
        return tuple(value)
    return ()


def _stage_mapping_get(mapping: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for candidate, value in items:
        if type(candidate) is str and candidate == key:
            return value
    return default


def _stage_float(value: object, *, default: float = 0.0) -> float:
    metric, reason = no_hook_finite_float(value, default=default, reason='invalid_stage_metric')
    return default if reason else metric


def sanitize_tag_part(value: object) -> str:
    text = _stage_lower_text(value)
    out = []
    for ch in text:
        if ch.isalnum():
            out.append(ch)
        elif ch in {'_','-','.'}:
            out.append('_')
    cleaned = ''.join(out).strip('_')
    return cleaned or 'unknown'


get_scan_extension = _contract_get_scan_extension

def normalize_stage(ext: object) -> str:
    ext = _stage_lower_text(ext)
    canonical = {'cs','binary','runtime','asset','image','archive','other','unknown'}
    if ext in canonical:
        return ext
    if ext == '.cs':
        return 'cs'
    if ext in {'.exe','.dll','.bin','.so','.dylib'}:
        return 'binary'
    if ext in {'.py','.js','.ps1','.bat','.cmd','.sh','.rpy','.rpyc','.rpyb','.rvdata','.rvdata2','.rxdata'}:
        return 'runtime'
    if ext in IMAGE_EXTENSIONS:
        return 'image'
    if ext in UNITY_CONTAINER_ASSET_EXTENSIONS or ext in {'.resx','.json','.xml','.ini','.cfg','.txt'} or ext in MEDIA_ASSET_EXTENSIONS or ext in FONT_ASSET_EXTENSIONS:
        return 'asset'
    if ext in {'.zip','.tar','.gz','.bz2','.tgz','.7z','.rar','.rpa'}:
        return 'archive'
    if ext:
        return 'other'
    return 'unknown'


def extract_router_stage(tags: object) -> str:
    """Return the router-declared stage only.

    Stage ownership is no longer inferred through caller-provided secondary routing.
    Callers that need path-derived routing must use ``effective_stage_for_path``
    so the secondary source is explicit and centrally owned here.
    """
    try:
        for tag in _stage_owned_items(tags):
            text = _stage_text(tag)
            if text.startswith('router_stage_'):
                return normalize_stage(text.replace('router_stage_', '', 1))
    except IO_CONFIGURATION_ERRORS as exc:
        record_suppressed_failure('stage_inference_failed', exc, domain='routing')
    return 'unknown'


def effective_stage_for_path(tags: object, path: object) -> str:
    """Resolve stage from router evidence, then canonical path extension."""
    routed = extract_router_stage(tags)
    if routed != 'unknown':
        return routed
    return normalize_stage(get_scan_extension(path))




CONTENT_RUNTIME_EVIDENCE_TAGS = frozenset({
    'powershell_exec', 'encoded_powershell', 'cmd_exec', 'process_exec',
    'script_execution', 'payload_execution', 'fileless_execution',
    'network_download_execute',
    'remote_payload_download',
    'process_injection', 'memory_write',
    'thread_execution', 'write_process_memory', 'create_remote_thread',
    'remote_thread_create', 'credential_dump_attempt', 'lsass_access',
    'mimikatz_credential_dump', 'amsi_scanbuffer_patch',
    'etw_eventwrite_patch', 'defender_disable', 'shadowcopy_delete',
})

def resolve_content_evidence_stage(stage: object, tags: object) -> str:
    """Promote passive text/config routing to runtime when content proves execution.

    Extension and magic ownership can classify .txt/.json/.cfg as passive assets.
    Once scanner-owned content evidence confirms executable behavior, the routed
    stage must reflect the observed runtime semantics so scoring and reporting do
    not apply passive-asset treatment to active attack content.
    """
    current = normalize_stage(stage)
    if current not in {'asset', 'unknown', 'other'}:
        return current
    observed = {text for item in _stage_owned_items(tags) if (text := _stage_lower_text(item))}
    if observed & CONTENT_RUNTIME_EVIDENCE_TAGS:
        return 'runtime'
    return current

def normalize_profile_extension(file_path: object) -> str:
    """Return the canonical per-profile extension bucket for a scan path.

    Profile learning owns extension buckets through this deterministic helper so
    model, detection, and routing code do not depend on routing/extensions.py or
    runtime publication side effects.
    """
    ext = get_scan_extension(file_path)
    return ext or '<no_ext>'

def choose_effective_stage(ext_stage: str, identity: Mapping[str, object]) -> str:
    magic_stage = _stage_lower_text(_stage_mapping_get(identity, 'magic_stage', 'unknown'), default='unknown')
    confidence = _stage_float(_stage_mapping_get(identity, 'confidence', 0.0))
    actual_category = _stage_lower_text(_stage_mapping_get(identity, 'actual_category', 'unknown'), default='unknown')
    mis_score = _stage_float(_stage_mapping_get(identity, 'misclassification_score', 0.0))
    if magic_stage in {'binary','archive','image','asset','runtime'} and confidence >= PLR2004N0_85 and magic_stage != ext_stage:
        return magic_stage
    if ext_stage in {'unknown','other'} and magic_stage in {'asset','runtime'} and confidence >= PLR2004N0_55:
        return magic_stage
    if mis_score > 0 and actual_category != 'unknown':
        routed = CLAIM_CATEGORY_STAGE.get(actual_category)
        if routed in {'binary','archive','image','asset','runtime'}:
            return routed
    if ext_stage in {'unknown','other'} and magic_stage != 'unknown':
        return magic_stage
    return ext_stage


def normalize_game_asset_suffix_extension(name: object) -> str | None:
    """Normalize archive/extractor-safe game asset suffixes for routing only.

    Handles preserved names like file.ogg_ or file.png_ without renaming the file.
    """
    try:
        n = _stage_lower_text(name)
        known = {
            '.ogg', '.oga', '.opus', '.mp3', '.wav', '.flac', '.m4a',
            '.aac', '.wma', '.png', '.jpg', '.jpeg', '.webp', '.gif',
            '.bmp', '.ttf', '.otf', '.fnt', '.json', '.txt', '.xml',
            '.rpy', '.rpyc', '.rpa', '.assets', '.asset', '.bundle',
            '.unity3d', '.resource', '.resources', '.ress'
        }
        if n.endswith('_'):
            base = n[:-1]
            for ext in sorted(known, key=len, reverse=True):
                if base.endswith(ext):
                    return ext
    except IO_CONFIGURATION_ERRORS as exc:
        record_suppressed_failure('extension_inference_failed', exc, domain='routing')
    return None
