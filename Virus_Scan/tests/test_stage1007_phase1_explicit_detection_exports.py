import ast
from pathlib import Path

from Virus_Scan.detection.chains.composite import behavior_taxonomy
from Virus_Scan.detection.registries import constants_defaults


_EXPECTED_BEHAVIOR_TAXONOMY_EXPORTS = tuple(sorted((
    "BLOCKCHAIN_ABUSE_TAGS",
    "BLOCKCHAIN_REPORT_ONLY_TAGS",
    "COMMAND_OBSERVATION_TAGS",
    "CREDENTIAL_OBSERVATION_TAGS",
    "DOWNLOAD_OBSERVATION_TAGS",
    "EXECUTION_OBSERVATION_TAGS",
    "EXFILTRATION_OBSERVATION_TAGS",
    "GAME_ENGINE_WEAK_TEXT_ENCODED_TAGS",
    "INJECTION_OBSERVATION_TAGS",
    "PERSISTENCE_OBSERVATION_TAGS",
)))

_EXPECTED_CONSTANT_DEFAULT_EXPORTS = tuple(sorted((
    'CONTEXTUAL_BASELINE_VERSION',
    'CONTEXTUAL_BASELINE_MIN_FILES',
    'CONTEXTUAL_BASELINE_COMMON_TAG_PROB',
    'CONTEXTUAL_BASELINE_STRONG_COMMON_TAG_PROB',
    'CONTEXTUAL_BASELINE_MAX_REDUCTION',
    'CONTEXTUAL_BASELINE_MIN_KEEP_WITHOUT_ANCHOR',
    'CONTEXTUAL_BASELINE_MIN_KEEP_WITH_ANCHOR',
    'CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS',
    'TRIAGE_LEARNING_BLOCK_TAGS',
    'CONTEXTUAL_DANGEROUS_ANCHOR_TAGS',
    'CONTEXTUAL_WEAK_NOISE_BUCKETS',
    'BEHAVIOR_MODEL_VERSION',
    'VECTOR_FEATURE_NAMES',
    'NON_EXECUTION_CAPABILITIES',
    'CONTAINER_EXECUTION_CAPABILITIES',
    'QUALITY_GATE_VERSION',
    'ENGINE_BASELINE_CONFIDENCE_THRESHOLD',
    'BASELINE_MATURITY_COLD_FILES',
    'BASELINE_MATURITY_WARM_FILES',
    'TAG_REPORTING_CANONICAL_NAMES',
    'CONFIRMED_API_HINTS',
)))


def _all_assignment_source(module_file: str) -> str:
    source = Path(module_file).read_text(encoding='utf-8')
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == '__all__'
            for target in node.targets
        ):
            return ast.get_source_segment(source, node) or ''
    raise AssertionError(f'no __all__ assignment found in {module_file}')


def test_stage1007_behavior_taxonomy_exports_are_explicit_and_preserve_contract():
    assert behavior_taxonomy.__all__ == _EXPECTED_BEHAVIOR_TAXONOMY_EXPORTS
    source = _all_assignment_source(behavior_taxonomy.__file__)
    assert 'globals()' not in source
    assert 'locals()' not in source
    assert 'tuple(name for name' not in source
    for name in _EXPECTED_BEHAVIOR_TAXONOMY_EXPORTS:
        assert hasattr(behavior_taxonomy, name)


def test_stage1007_detection_constants_exports_are_explicit_and_preserve_contract():
    assert constants_defaults.__all__ == _EXPECTED_CONSTANT_DEFAULT_EXPORTS
    source = _all_assignment_source(constants_defaults.__file__)
    assert 'globals()' not in source
    assert 'locals()' not in source
    assert 'tuple(name for name' not in source
    for name in _EXPECTED_CONSTANT_DEFAULT_EXPORTS:
        assert hasattr(constants_defaults, name)
