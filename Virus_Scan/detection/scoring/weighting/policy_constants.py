"""Immutable tag scoring policy constants owned by detection scoring."""

from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.utils.tagging import norm_lower_set

TAG_SCAN_RECOVERABLE_EXCEPTIONS = (OSError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError)


def norm_lower_tag_set(tags: object) -> object:
    return norm_lower_set(tags)


CONTAINER_EXECUTION_CAPABILITIES = frozenset(detection_registry_value('CONTAINER_EXECUTION_CAPABILITIES', frozenset({'container'})))
VECTOR_FEATURE_NAMES = tuple(detection_registry_value('VECTOR_FEATURE_NAMES', ()))
BROAD_UNVALIDATED_TAGS = frozenset(detection_registry_value('BROAD_UNVALIDATED_TAGS', frozenset({'network_activity', 'url_present', 'reference_url', 'encoded_data_context', 'payload_decode_candidate', 'packed_or_obfuscated', 'high_entropy_packed'})))
PICKLE_GRAPH_PROTECTED_TAGS = frozenset(detection_registry_value('PICKLE_GRAPH_PROTECTED_TAGS', frozenset({'pickle_reduce_opcode'})))
PICKLE_GRAPH_PROOF_TAGS = frozenset(detection_registry_value('PICKLE_GRAPH_PROOF_TAGS', frozenset({'pickle_opcode_graph_analyzed', 'pickle_dangerous_global'})))
RPYC_HIGH_RISK_TAGS = frozenset(detection_registry_value('RPYC_HIGH_RISK_TAGS', frozenset({'pickle_deserialization_context'})))
ASSET_RESOURCE_FETCH_TERMS = tuple(detection_registry_value('ASSET_RESOURCE_FETCH_TERMS', ('xmlhttprequest', 'fetch(', 'image.src', 'audio.src', 'video.src', '.src =', 'fs.writefile')))
ASSET_RESOURCE_PATH_TERMS = tuple(detection_registry_value('ASSET_RESOURCE_PATH_TERMS', ('assets/', 'www/', 'game/', '.png', '.jpg', '.ogg', '.mp3', '.json', '.rpa', '.assets')))
RESOURCE_CACHE_TERMS = tuple(detection_registry_value('RESOURCE_CACHE_TERMS', ('cache', 'cached', 'persistentdatapath', 'localstorage', 'indexeddb')))
REMOTE_PAYLOAD_DOWNLOAD_TERMS = tuple(detection_registry_value('REMOTE_PAYLOAD_DOWNLOAD_TERMS', ('download', 'downloadstring', 'downloadfile', 'fetch(', 'xmlhttprequest', 'urlopen', 'invoke-webrequest')))
VALID_STAGES = frozenset({'text', 'binary', 'script', 'archive', 'image', 'asset', 'runtime', 'unknown'})
STAGE_WEIGHT = MappingProxyType(dict(detection_registry_value('STAGE_WEIGHT', MappingProxyType({'cs': 1.0, 'binary': 1.55, 'runtime': 1.25, 'asset': 1.2, 'image': 0.8, 'archive': 1.3, 'renpy': 1.2, 'rpgm': 1.2, 'other': 1.0, 'unknown': 1.0}))))
REMOTE_PAYLOAD_FILE_TERMS = tuple(detection_registry_value('REMOTE_PAYLOAD_FILE_TERMS', ('.exe', '.dll', '.ps1', '.bat', '.cmd', 'payload', 'stage', 'temp', 'appdata')))
C2_TASKING_TERMS = tuple(detection_registry_value('C2_TASKING_TERMS', ('command', 'cmd', 'task', 'tasking', 'beacon', 'checkin', 'heartbeat', 'shell')))
COMMAND_EXECUTION_TERMS = tuple(detection_registry_value('COMMAND_EXECUTION_TERMS', ('process.start', 'os.system', 'subprocess', 'child_process', 'exec(', 'eval(', 'powershell', 'cmd.exe')))
TAG_WEAK_CONTEXT_ONLY = frozenset(detection_registry_value('TAG_WEAK_CONTEXT_ONLY', frozenset({'url_present', 'network_url', 'asset_resource_fetch', 'browser_xhr_fetch', 'network_activity', 'reference_url', 'encoded_data_context', 'payload_decode_candidate', 'encoded_payload_candidate', 'decoded_payload_observed', 'decoded_base64_blob', 'compressed_payload_candidate', 'high_entropy_packed', 'very_high_entropy', 'renpy', 'rpgm', 'unity_engine', 'unity_asset', 'managed_dotnet', 'node_runtime', 'nwjs', 'pickle_deserialization_context', 'pickle_fast_text_hint', 'python_bytecode_or_script'})))
TAG_STRUCTURAL_ONLY = frozenset(detection_registry_value('TAG_STRUCTURAL_ONLY', frozenset({'extension_mismatch', 'asset_extension_magic_mismatch', 'extension_magic_type_mismatch', 'filetype_misclassification', 'asset_deep_scan_escalated', 'embedded_command_or_url', 'embedded_pe_signature', 'possible_appended_payload', 'packer_marker', 'packed_or_obfuscated', 'engine_runtime_library', 'runtime_library', 'python_runtime_binary', 'python_runtime_library', 'renpy_runtime_library'})))
TAG_BEHAVIOR_SCOREABLE = frozenset(detection_registry_value('TAG_BEHAVIOR_SCOREABLE', frozenset({'process_exec', 'script_execution', 'dynamic_execution', 'powershell_exec', 'encoded_powershell', 'cmd_exec', 'network_download', 'remote_payload_download', 'http_upload', 'network_exfiltration', 'token_exfiltration', 'network_c2', 'backdoor_or_c2', 'remote_command_channel', 'scheduled_task', 'registry_persistence', 'startup_persistence', 'service_create', 'credential_dump_attempt', 'token_secret_access', 'memory_write', 'write_process_memory', 'remote_thread_create', 'create_remote_thread', 'defender_disable', 'amsi_bypass_attempt', 'etw_bypass_attempt', 'encoded_payload', 'embedded_pe_payload', 'confirmed_embedded_pe_payload', 'decoded_pe_payload', 'image_payload_confirmed', 'archive_dropper', 'dropper_behavior', 'embedded_archive_payload', 'macro_office', 'office_macro_execution', 'keylogging_behavior', 'input_capture'})))
TAG_CHAIN_LINK_REQUIRED = frozenset(detection_registry_value('TAG_CHAIN_LINK_REQUIRED', TAG_WEAK_CONTEXT_ONLY | TAG_STRUCTURAL_ONLY))
CONCRETE_SCORE_TAGS = frozenset(detection_registry_value('CONCRETE_SCORE_TAGS', TAG_BEHAVIOR_SCOREABLE)) - TAG_CHAIN_LINK_REQUIRED
SUPPORT_ONLY_SCORE_TAGS = frozenset(detection_registry_value('SUPPORT_ONLY_SCORE_TAGS', TAG_WEAK_CONTEXT_ONLY | TAG_STRUCTURAL_ONLY))
TAG_RISK_SCORES = MappingProxyType(dict(detection_registry_value('TAG_RISK_SCORES', MappingProxyType({}))))
HIGH_RISK_BUCKETS = frozenset(detection_registry_value('HIGH_RISK_BUCKETS', frozenset({'os_execution', 'credential', 'persistence', 'injection', 'evasion'})))
CONTEXTUAL_BASELINE_VERSION = int(detection_registry_value('CONTEXTUAL_BASELINE_VERSION', 1))
CONTEXTUAL_BASELINE_MIN_FILES = int(detection_registry_value('CONTEXTUAL_BASELINE_MIN_FILES', 25))
CONTEXTUAL_BASELINE_COMMON_TAG_PROB = float(detection_registry_value('CONTEXTUAL_BASELINE_COMMON_TAG_PROB', 0.72))
CONTEXTUAL_BASELINE_STRONG_COMMON_TAG_PROB = float(detection_registry_value('CONTEXTUAL_BASELINE_STRONG_COMMON_TAG_PROB', 0.9))
CONTEXTUAL_BASELINE_MAX_REDUCTION = float(detection_registry_value('CONTEXTUAL_BASELINE_MAX_REDUCTION', 18.0))
CONTEXTUAL_BASELINE_MIN_KEEP_WITHOUT_ANCHOR = float(detection_registry_value('CONTEXTUAL_BASELINE_MIN_KEEP_WITHOUT_ANCHOR', 8.0))
CONTEXTUAL_BASELINE_MIN_KEEP_WITH_ANCHOR = float(detection_registry_value('CONTEXTUAL_BASELINE_MIN_KEEP_WITH_ANCHOR', 32.0))
CONTEXTUAL_DANGEROUS_ANCHOR_TAGS = frozenset(detection_registry_value('CONTEXTUAL_DANGEROUS_ANCHOR_TAGS', frozenset()))
CONTEXTUAL_WEAK_NOISE_BUCKETS = frozenset(detection_registry_value('CONTEXTUAL_WEAK_NOISE_BUCKETS', frozenset({'reference', 'resource', 'noise'})))
CONTEXT_AMPLIFIER_VERSION = str(detection_registry_value('CONTEXT_AMPLIFIER_VERSION', 'context_confidence_amplifier_v1_capped'))
VECTOR_CLUSTER_MAX_BONUS = float(detection_registry_value('VECTOR_CLUSTER_MAX_BONUS', 8.0))
CONTEXT_CORROBORATION_MAX_BONUS = float(detection_registry_value('CONTEXT_CORROBORATION_MAX_BONUS', 10.0))
COMBINED_CONTEXT_MAX_BONUS = float(detection_registry_value('COMBINED_CONTEXT_MAX_BONUS', 15.0))
MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST = int(detection_registry_value('MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST', 2))
MIN_SCORE_FOR_CONTEXT_BOOST = float(detection_registry_value('MIN_SCORE_FOR_CONTEXT_BOOST', 25.0))
TAG_ROLE_EXPECTED_BEHAVIOR = MappingProxyType(dict(detection_registry_value('TAG_ROLE_EXPECTED_BEHAVIOR', MappingProxyType({
    'weak_context': 'report only; can support chains but cannot score alone',
    'structural': 'file/container/runtime structure; can explain why deep scan happened but cannot score alone',
    'behavior': 'concrete action/API/command; may score with confidence and rarity gates',
    'chain_projection': 'publication-only legacy conclusion; canonical ChainEvidence owns all scoring and floors',
    'unknown': 'reported for audit, but treated as support-only until mapped',
}))))
TAG_AUDIT_VERSION = detection_registry_value('TAG_AUDIT_VERSION', 'tag_chain_audit_guardrails_v2')

__all__ = (
    'ASSET_RESOURCE_FETCH_TERMS',
    'ASSET_RESOURCE_PATH_TERMS',
    'BROAD_UNVALIDATED_TAGS',
    'C2_TASKING_TERMS',
    'COMBINED_CONTEXT_MAX_BONUS',
    'COMMAND_EXECUTION_TERMS',
    'CONCRETE_SCORE_TAGS',
    'CONTAINER_EXECUTION_CAPABILITIES',
    'CONTEXTUAL_BASELINE_COMMON_TAG_PROB',
    'CONTEXTUAL_BASELINE_MAX_REDUCTION',
    'CONTEXTUAL_BASELINE_MIN_FILES',
    'CONTEXTUAL_BASELINE_MIN_KEEP_WITHOUT_ANCHOR',
    'CONTEXTUAL_BASELINE_MIN_KEEP_WITH_ANCHOR',
    'CONTEXTUAL_BASELINE_STRONG_COMMON_TAG_PROB',
    'CONTEXTUAL_BASELINE_VERSION',
    'CONTEXTUAL_DANGEROUS_ANCHOR_TAGS',
    'CONTEXTUAL_WEAK_NOISE_BUCKETS',
    'CONTEXT_AMPLIFIER_VERSION',
    'CONTEXT_CORROBORATION_MAX_BONUS',
    'HIGH_RISK_BUCKETS',
    'MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST',
    'MIN_SCORE_FOR_CONTEXT_BOOST',
    'PICKLE_GRAPH_PROOF_TAGS',
    'PICKLE_GRAPH_PROTECTED_TAGS',
    'REMOTE_PAYLOAD_DOWNLOAD_TERMS',
    'REMOTE_PAYLOAD_FILE_TERMS',
    'RESOURCE_CACHE_TERMS',
    'RPYC_HIGH_RISK_TAGS',
    'STAGE_WEIGHT',
    'SUPPORT_ONLY_SCORE_TAGS',
    'TAG_AUDIT_VERSION',
    'TAG_BEHAVIOR_SCOREABLE',
    'TAG_CHAIN_LINK_REQUIRED',
    'TAG_RISK_SCORES',
    'TAG_ROLE_EXPECTED_BEHAVIOR',
    'TAG_SCAN_RECOVERABLE_EXCEPTIONS',
    'TAG_STRUCTURAL_ONLY',
    'TAG_WEAK_CONTEXT_ONLY',
    'VALID_STAGES',
    'VECTOR_CLUSTER_MAX_BONUS',
    'VECTOR_FEATURE_NAMES',
    'norm_lower_tag_set',
)
