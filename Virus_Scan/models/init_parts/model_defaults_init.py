"""analytical/model defaults: reliability, temporal, clustering, scoring, adaptive fusion.

Split from init_runtime.top_level.run_top_level_init without changing the
original statement order inside this initializer group. Each initializer updates
the shared runtime STATE exactly as the generated Stage 10 initializer did.
"""
import re
from collections import Counter, defaultdict, deque
from Virus_Scan.runtime.init_state import publish_init_values
from Virus_Scan.contracts.env_config import float_env
from Virus_Scan.contracts.api_behavior import API_GROUPS as CANONICAL_API_GROUPS, build_api_regex as canonical_build_api_regex



def _analytical_model_defaults() -> tuple[tuple[str, object], ...]:
    ANALYTICAL_EVIDENCE_SCHEMA_VERSION = '2.1'
    ODDITY_CALIBRATION_VERSION = 'format_zscore_v1'
    GRAPH_CONFIDENCE_VERSION = 'graph_context_uncertainty_v1'
    CLUSTER_EMBEDDING_CONFIDENCE_VERSION = 'cluster_embedding_overlay_v1'
    PROBABILISTIC_SEMANTICS_VERSION = 'probabilistic_semantics_v1'
    CAUSAL_ENTITY_MODEL_VERSION = 'causal_entity_lineage_v1'
    COUNTERFACTUAL_SUPPRESSION_VERSION = 'counterfactual_suppression_v1'
    RELIABILITY_TO_NUMERIC = {'deterministic': 0.95, 'strong_heuristic': 0.82, 'medium_heuristic': 0.62, 'weak_heuristic': 0.35, 'contextual': 0.2}
    EVIDENCE_STRENGTH_TO_LIKELIHOOD = {'deterministic': 0.92, 'strong_heuristic': 0.78, 'medium_heuristic': 0.56, 'weak_heuristic': 0.3, 'contextual': 0.18}
    CORRELATION_GROUP_KEYWORDS = [('powershell_encoded', ('powershell', 'encodedcommand', 'encoded_powershell', 'encoded_powershell', '-enc')), ('base64_decode', ('base64', 'frombase64', 'decoded_base64', 'encoded_payload')), ('compression_decode', ('gzip', 'deflate', 'zlib', 'compressed_payload', 'archive_recursion')), ('process_execution', ('process_exec', 'script_execution', 'shell_exec', 'wscript', 'mshta', 'rundll32', 'regsvr32')), ('credential_access', ('credential', 'lsass', 'token_secret', 'browser_profile', 'password', 'cookie')), ('network_transfer', ('network', 'download', 'http', 'url', 'c2', 'exfil')), ('persistence', ('persistence', 'run_key', 'scheduled_task', 'schtasks', 'service')), ('stego_media', ('stego', 'appended', 'overlay', 'image', 'png', 'lsb')), ('packing_obfuscation', ('packed', 'packer', 'obfus', 'xor', 'crypt', 'entropy'))]
    EVIDENCE_RELIABILITY_CLASSES = {'deterministic': {'confidence_floor': 0.9, 'description': 'high-specificity malware or exploit behavior'}, 'strong_heuristic': {'confidence_floor': 0.7, 'description': 'strong suspicious behavior or tool signature'}, 'medium_heuristic': {'confidence_floor': 0.45, 'description': 'moderate suspicious indicator requiring corroboration'}, 'weak_heuristic': {'confidence_floor': 0.1, 'description': 'weak/contextual indicator, capped when alone'}, 'contextual': {'confidence_floor': 0.05, 'description': 'context-only signal, never decisive alone'}}
    FORMAT_ODDITY_BASELINES = {'png': {'entropy_mean': 7.25, 'entropy_std': 0.45}, 'jpg': {'entropy_mean': 7.55, 'entropy_std': 0.35}, 'jpeg': {'entropy_mean': 7.55, 'entropy_std': 0.35}, 'webp': {'entropy_mean': 7.45, 'entropy_std': 0.4}, 'gif': {'entropy_mean': 6.6, 'entropy_std': 0.65}, 'ogg': {'entropy_mean': 7.35, 'entropy_std': 0.45}, 'mp3': {'entropy_mean': 7.4, 'entropy_std': 0.45}, 'wav': {'entropy_mean': 6.2, 'entropy_std': 0.9}, 'zip': {'entropy_mean': 7.7, 'entropy_std': 0.25}, '7z': {'entropy_mean': 7.85, 'entropy_std': 0.15}, 'rar': {'entropy_mean': 7.8, 'entropy_std': 0.2}, 'exe': {'entropy_mean': 6.4, 'entropy_std': 0.95}, 'dll': {'entropy_mean': 6.35, 'entropy_std': 0.95}, 'rpyc': {'entropy_mean': 6.8, 'entropy_std': 0.75}, 'rpa': {'entropy_mean': 7.35, 'entropy_std': 0.55}, 'txt': {'entropy_mean': 4.6, 'entropy_std': 1.1}, 'json': {'entropy_mean': 4.8, 'entropy_std': 1.0}, 'xml': {'entropy_mean': 4.7, 'entropy_std': 1.0}, 'default': {'entropy_mean': 6.2, 'entropy_std': 1.2}}
    return (
        ('ANALYTICAL_EVIDENCE_SCHEMA_VERSION', ANALYTICAL_EVIDENCE_SCHEMA_VERSION),
        ('ODDITY_CALIBRATION_VERSION', ODDITY_CALIBRATION_VERSION),
        ('GRAPH_CONFIDENCE_VERSION', GRAPH_CONFIDENCE_VERSION),
        ('CLUSTER_EMBEDDING_CONFIDENCE_VERSION', CLUSTER_EMBEDDING_CONFIDENCE_VERSION),
        ('PROBABILISTIC_SEMANTICS_VERSION', PROBABILISTIC_SEMANTICS_VERSION),
        ('CAUSAL_ENTITY_MODEL_VERSION', CAUSAL_ENTITY_MODEL_VERSION),
        ('COUNTERFACTUAL_SUPPRESSION_VERSION', COUNTERFACTUAL_SUPPRESSION_VERSION),
        ('RELIABILITY_TO_NUMERIC', RELIABILITY_TO_NUMERIC),
        ('EVIDENCE_STRENGTH_TO_LIKELIHOOD', EVIDENCE_STRENGTH_TO_LIKELIHOOD),
        ('CORRELATION_GROUP_KEYWORDS', CORRELATION_GROUP_KEYWORDS),
        ('EVIDENCE_RELIABILITY_CLASSES', EVIDENCE_RELIABILITY_CLASSES),
        ('FORMAT_ODDITY_BASELINES', FORMAT_ODDITY_BASELINES),
    )

def _decode_pickle_model_defaults() -> tuple[tuple[str, object], ...]:
    DECODE_LAYER_MAX_CANDIDATES = 64
    DECODE_LAYER_MAX_TEXT_BYTES = 262144
    DECODE_LAYER_MAX_DEPTH = 5
    DECODE_LAYER_MIN_B64_CHARS = 32
    DECODE_LAYER_MIN_HEX_CHARS = 64
    DECODE_LAYER_DEBUG = False
    PICKLE_DECODE_MAX_FILE_BYTES = 8 * 1024 * 1024
    PICKLE_DECODE_MAX_OFFSETS = 32
    PICKLE_DECODE_MAX_OBJECTS = 64
    PICKLE_DECODE_MAX_DECODED_BYTES = 512 * 1024
    PICKLE_DECODE_MIN_PAYLOAD_BYTES = 24
    RPA_MEMBER_MAX_COUNT = 96
    RPA_MEMBER_MAX_BYTES = 2 * 1024 * 1024
    RPA_INDEX_MAX_BYTES = 2 * 1024 * 1024
    PICKLE_DANGEROUS_GLOBALS = {'os.system', 'posix.system', 'nt.system', 'subprocess.popen', 'subprocess.call', 'subprocess.run', 'subprocess.check_call', 'subprocess.check_output', 'builtins.eval', 'builtins.exec', 'builtins.compile', 'builtins.__import__', 'builtins.getattr', '__builtin__.eval', '__builtin__.exec', '__builtin__.compile', '__builtin__.__import__', '__builtin__.getattr', 'eval', 'exec', 'compile', '__import__', 'getattr', 'runpy.run_path', 'runpy.run_module', 'importlib.import_module', 'marshal.loads', 'pickle.loads', 'pickle.load', 'cloudpickle.loads', 'dill.loads', 'types.functiontype', 'types.codetype', 'operator.attrgetter', 'operator.methodcaller'}
    PICKLE_SUSPICIOUS_GLOBAL_PARTS = {'system', 'popen', 'subprocess', 'eval', 'exec', 'compile', '__import__', 'getattr', 'run_path', 'run_module', 'import_module', 'loads', 'find_class', 'persistent_load', 'functiontype', 'codetype', 'attrgetter', 'methodcaller'}
    PICKLE_SAFE_RECONSTRUCT_GLOBALS = {'collections.defaultdict', '__builtin__.list', 'builtins.list', '__builtin__.dict', 'builtins.dict', '__builtin__.set', 'builtins.set', '__builtin__.tuple', 'builtins.tuple', 'copy_reg._reconstructor', 'copyreg._reconstructor'}
    PICKLE_SAFE_RECONSTRUCT_PREFIXES = ('renpy.ast.', 'renpy.atl.', 'renpy.display.', 'renpy.text.', 'renpy.python.', 'renpy.sl2.', 'renpy.style.', 'renpy.audio.', 'renpy.character.')
    PICKLE_DANGEROUS_GLOBAL_RE = re.compile('(?:^|\\.)(?:system|popen|check_call|check_output|eval|exec|compile|__import__|getattr|loads|find_class|persistent_load|functiontype|codetype|attrgetter|methodcaller)$')
    PICKLE_LITERAL_JOIN_MAX = 128
    PICKLE_FRAGMENT_MIN_B64_CHARS = 20
    RENPY_PICKLE_EXTENSIONS = {'.rpa', '.rpy', '.rpyc', '.rpyb', '.rpym', '.rpymc'}
    UMIGE_B64_LONG_RE = re.compile('(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{80,}={0,2})(?![A-Za-z0-9+/=_-])')
    UMIGE_IPV4_RE = re.compile('\\b(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}\\b')
    return (
        ('DECODE_LAYER_MAX_CANDIDATES', DECODE_LAYER_MAX_CANDIDATES),
        ('DECODE_LAYER_MAX_TEXT_BYTES', DECODE_LAYER_MAX_TEXT_BYTES),
        ('DECODE_LAYER_MAX_DEPTH', DECODE_LAYER_MAX_DEPTH),
        ('DECODE_LAYER_MIN_B64_CHARS', DECODE_LAYER_MIN_B64_CHARS),
        ('DECODE_LAYER_MIN_HEX_CHARS', DECODE_LAYER_MIN_HEX_CHARS),
        ('DECODE_LAYER_DEBUG', DECODE_LAYER_DEBUG),
        ('PICKLE_DECODE_MAX_FILE_BYTES', PICKLE_DECODE_MAX_FILE_BYTES),
        ('PICKLE_DECODE_MAX_OFFSETS', PICKLE_DECODE_MAX_OFFSETS),
        ('PICKLE_DECODE_MAX_OBJECTS', PICKLE_DECODE_MAX_OBJECTS),
        ('PICKLE_DECODE_MAX_DECODED_BYTES', PICKLE_DECODE_MAX_DECODED_BYTES),
        ('PICKLE_DECODE_MIN_PAYLOAD_BYTES', PICKLE_DECODE_MIN_PAYLOAD_BYTES),
        ('RPA_MEMBER_MAX_COUNT', RPA_MEMBER_MAX_COUNT),
        ('RPA_MEMBER_MAX_BYTES', RPA_MEMBER_MAX_BYTES),
        ('RPA_INDEX_MAX_BYTES', RPA_INDEX_MAX_BYTES),
        ('PICKLE_DANGEROUS_GLOBALS', PICKLE_DANGEROUS_GLOBALS),
        ('PICKLE_SUSPICIOUS_GLOBAL_PARTS', PICKLE_SUSPICIOUS_GLOBAL_PARTS),
        ('PICKLE_SAFE_RECONSTRUCT_GLOBALS', PICKLE_SAFE_RECONSTRUCT_GLOBALS),
        ('PICKLE_SAFE_RECONSTRUCT_PREFIXES', PICKLE_SAFE_RECONSTRUCT_PREFIXES),
        ('PICKLE_DANGEROUS_GLOBAL_RE', PICKLE_DANGEROUS_GLOBAL_RE),
        ('PICKLE_LITERAL_JOIN_MAX', PICKLE_LITERAL_JOIN_MAX),
        ('PICKLE_FRAGMENT_MIN_B64_CHARS', PICKLE_FRAGMENT_MIN_B64_CHARS),
        ('RENPY_PICKLE_EXTENSIONS', RENPY_PICKLE_EXTENSIONS),
        ('UMIGE_B64_LONG_RE', UMIGE_B64_LONG_RE),
        ('UMIGE_IPV4_RE', UMIGE_IPV4_RE),
    )

def _temporal_cluster_model_defaults() -> tuple[tuple[str, object], ...]:
    TRANSITION_COUNTS = defaultdict(lambda: defaultdict(int))
    GLOBAL_TAG_BASELINE = defaultdict(int)
    GLOBAL_TAG_PAIR_BASELINE = defaultdict(int)
    FILETYPE_BASELINE = defaultdict(Counter)
    ENGINE_CONTEXT_PRIOR = {'unity': 0.0, 'renpy': 0.0, 'rpgm': 0.0, 'media': 0.0, 'unknown': 1.0}
    ENGINE_FILE_CONTEXT_CUES = {'renpy': {'extensions': {'.rpy', '.rpyc', '.rpyb', '.rpa'}, 'path_markers': ('/renpy/', 'renpy/', 'game/scripts', 'librenpython'), 'string_markers': ('renpy', "ren'py", 'renpy.python'), 'tag_markers': {'renpy', 'renpy_bytecode', 'renpy_archive', 'renpy_script'}}, 'unity': {'extensions': {'.assets', '.unity3d', '.resource', '.ress', '.bundle'}, 'path_markers': ('unityplayer.dll', 'gameassembly.dll', 'globalgamemanagers', 'managed/assembly-csharp.dll', 'managed\\assembly-csharp.dll', 'il2cpp_data', 'unitycrashhandler'), 'string_markers': ('unity', 'unityplayer', 'il2cpp', 'mono/', 'assembly-csharp'), 'tag_markers': {'unity', 'unity_engine', 'unity_asset', 'il2cpp', 'managed_dotnet'}}, 'rpgm': {'extensions': {'.rvdata', '.rvdata2', '.rxdata', '.rgss2a', '.rgss3a'}, 'path_markers': ('www/data', 'www/js', 'js/plugins', 'game.rgss', 'rpg_core.js', 'rpg_managers.js'), 'string_markers': ('rgss', 'rpg maker', 'rpg_core', 'rpg_managers', 'rmmv', 'rmmz'), 'tag_markers': {'rpgm', 'rpg_maker', 'rgss', 'rpgm_js'}}, 'media': {'extensions': {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tif', '.tiff', '.ico', '.dds', '.ktx', '.ktx2', '.pvr', '.qoi', '.tga', '.mp3', '.wav', '.ogg', '.oga', '.opus', '.flac', '.mp4', '.m4v', '.m4a', '.mov', '.avi', '.webm', '.mkv'}, 'path_markers': ('/images/', '/image/', '/audio/', '/music/', '/sounds/', '/sfx/', '/videos/', '/movies/', '/media/'), 'string_markers': ('png', 'jpeg', 'id3', 'ogg', 'webp', 'riff', 'ftyp', 'matroska'), 'tag_markers': {'media_asset', 'image_asset', 'audio_asset', 'video_asset', 'stego_payload_suspect', 'embedded_payload_after_eof'}}}
    CLUSTER_HALF_LIFE_SEC = float(86400.0 * 14.0)
    API_GROUPS = CANONICAL_API_GROUPS
    API_REGEX = canonical_build_api_regex(API_GROUPS)
    return (
        ('TRANSITION_COUNTS', TRANSITION_COUNTS),
        ('GLOBAL_TAG_BASELINE', GLOBAL_TAG_BASELINE),
        ('GLOBAL_TAG_PAIR_BASELINE', GLOBAL_TAG_PAIR_BASELINE),
        ('FILETYPE_BASELINE', FILETYPE_BASELINE),
        ('ENGINE_CONTEXT_PRIOR', ENGINE_CONTEXT_PRIOR),
        ('ENGINE_FILE_CONTEXT_CUES', ENGINE_FILE_CONTEXT_CUES),
        ('CLUSTER_HALF_LIFE_SEC', CLUSTER_HALF_LIFE_SEC),
        ('API_GROUPS', API_GROUPS),
        ('API_REGEX', API_REGEX),
    )

def _scoring_model_defaults() -> tuple[tuple[str, object], ...]:
    LAYER_WEIGHTS = {'quick_static': 0.28, 'stage_timeline': 0.22, 'graph_relationships': 0.2, 'threat_intel': 0.3}
    CALIBRATED_SCORE_VERSION = 'sigmoid_v3_chain_calibrated'
    CALIBRATED_SCORE_THRESHOLDS = {'benign_clean': (0.0, 24.9999), 'low_confidence': (25.0, 49.9999), 'high_confidence': (50.0, 74.9999), 'malicious': (75.0, 100.0)}
    CALIBRATED_SCORE_VERSION = 'log_odds_v4_adaptive_calibrated'
    ADAPTIVE_WEIGHT_VERSION = 'adaptive_weights_v1_profile_markov_cluster'
    ADAPTIVE_WEIGHT_MIN_HISTORY = 8
    ADAPTIVE_WEIGHT_BOUNDS = {'quick_static': (0.18, 0.38), 'stage_timeline': (0.14, 0.34), 'graph_relationships': (0.06, 0.22), 'threat_intel': (0.2, 0.42)}
    ADAPTIVE_LEARNED_MODEL_STATIC_VERSION = 'adaptive_learned_model_static_rolling_v1'
    ADAPTIVE_LEARNED_MODEL_MIN_WEIGHT = 0.15
    ADAPTIVE_LEARNED_MODEL_MAX_WEIGHT = 0.8
    ADAPTIVE_LEARNED_MODEL_WEAK_EVIDENCE_CAP = 0.25
    ADAPTIVE_LEARNED_MODEL_SINGLE_ANCHOR_CAP = 0.4
    ADAPTIVE_LEARNED_MODEL_IMMATURE_CAP = 0.35
    ADAPTIVE_LEARNED_MODEL_CONTRADICTION_CAP = 0.3
    CONTEXT_AMPLIFIER_VERSION = 'context_confidence_amplifier_v1_capped'
    VECTOR_CLUSTER_MAX_BONUS = 8.0
    CONTEXT_CORROBORATION_MAX_BONUS = 10.0
    COMBINED_CONTEXT_MAX_BONUS = 15.0
    MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST = 2
    MIN_CLUSTER_MEMBERS_FOR_CONTEXT = 4
    MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT = 0.6
    MIN_SCORE_FOR_CONTEXT_BOOST = 25.0
    return (
        ('LAYER_WEIGHTS', LAYER_WEIGHTS),
        ('CALIBRATED_SCORE_VERSION', CALIBRATED_SCORE_VERSION),
        ('CALIBRATED_SCORE_THRESHOLDS', CALIBRATED_SCORE_THRESHOLDS),
        ('CALIBRATED_SCORE_VERSION', CALIBRATED_SCORE_VERSION),
        ('ADAPTIVE_WEIGHT_VERSION', ADAPTIVE_WEIGHT_VERSION),
        ('ADAPTIVE_WEIGHT_MIN_HISTORY', ADAPTIVE_WEIGHT_MIN_HISTORY),
        ('ADAPTIVE_WEIGHT_BOUNDS', ADAPTIVE_WEIGHT_BOUNDS),
        ('ADAPTIVE_LEARNED_MODEL_STATIC_VERSION', ADAPTIVE_LEARNED_MODEL_STATIC_VERSION),
        ('ADAPTIVE_LEARNED_MODEL_MIN_WEIGHT', ADAPTIVE_LEARNED_MODEL_MIN_WEIGHT),
        ('ADAPTIVE_LEARNED_MODEL_MAX_WEIGHT', ADAPTIVE_LEARNED_MODEL_MAX_WEIGHT),
        ('ADAPTIVE_LEARNED_MODEL_WEAK_EVIDENCE_CAP', ADAPTIVE_LEARNED_MODEL_WEAK_EVIDENCE_CAP),
        ('ADAPTIVE_LEARNED_MODEL_SINGLE_ANCHOR_CAP', ADAPTIVE_LEARNED_MODEL_SINGLE_ANCHOR_CAP),
        ('ADAPTIVE_LEARNED_MODEL_IMMATURE_CAP', ADAPTIVE_LEARNED_MODEL_IMMATURE_CAP),
        ('ADAPTIVE_LEARNED_MODEL_CONTRADICTION_CAP', ADAPTIVE_LEARNED_MODEL_CONTRADICTION_CAP),
        ('CONTEXT_AMPLIFIER_VERSION', CONTEXT_AMPLIFIER_VERSION),
        ('VECTOR_CLUSTER_MAX_BONUS', VECTOR_CLUSTER_MAX_BONUS),
        ('CONTEXT_CORROBORATION_MAX_BONUS', CONTEXT_CORROBORATION_MAX_BONUS),
        ('COMBINED_CONTEXT_MAX_BONUS', COMBINED_CONTEXT_MAX_BONUS),
        ('MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST', MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST),
        ('MIN_CLUSTER_MEMBERS_FOR_CONTEXT', MIN_CLUSTER_MEMBERS_FOR_CONTEXT),
        ('MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT', MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT),
        ('MIN_SCORE_FOR_CONTEXT_BOOST', MIN_SCORE_FOR_CONTEXT_BOOST),
    )

def init_model_defaults() -> object:
    publish_init_values(
        _analytical_model_defaults()
        + _decode_pickle_model_defaults()
        + _temporal_cluster_model_defaults()
        + _scoring_model_defaults()
    )
    return publish_init_values(())

__all__ = ('init_model_defaults',)
