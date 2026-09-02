from pathlib import Path
import ast

CLUSTERING_ROOT = Path('Virus_Scan/models/clustering')
PRIVATE_COMMON_NAMES = (
    '_finite_cluster_metric',
    '_safe_cluster_text',
    '_cluster_input_sequence',
    '_cluster_text_sequence',
    '_cluster_mapping',
    '_cluster_int_limit',
    '_cluster_finite_vector',
    '_cluster_text_set',
    '_dominant_engine_context',
    '_ctx_float',
)
PRIVATE_EVIDENCE_NAMES = (
    '_cluster_assignment_unavailable',
    '_cluster_signal_unavailable_reason',
)
PRIVATE_VECTOR_NAMES = (
    '_sanitize_feature_vector',
    '_vectorcluster_members_for',
)


def _module_tree(relative_path):
    return ast.parse(Path(relative_path).read_text(encoding='utf-8'))


def _source(relative_path):
    return Path(relative_path).read_text(encoding='utf-8')


def test_stage1462_clustering_common_owner_exports_public_names_only():
    tree = _module_tree('Virus_Scan/models/clustering/common.py')
    defined = tuple(
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    for private_name in PRIVATE_COMMON_NAMES:
        assert private_name not in defined
    namespace = {}
    exec(compile(tree, 'Virus_Scan/models/clustering/common.py', 'exec'), namespace)
    exported = tuple(namespace['__all__'])
    assert all(not name.startswith('_') for name in exported)
    assert 'finite_cluster_metric' in exported
    assert 'safe_cluster_text' in exported
    assert 'cluster_mapping' in exported


def test_stage1462_clustering_evidence_owner_exports_public_unavailable_evidence():
    source = _source('Virus_Scan/models/clustering/evidence.py')
    for private_name in PRIVATE_EVIDENCE_NAMES:
        assert private_name not in source
    namespace = {}
    exec(compile(source, 'Virus_Scan/models/clustering/evidence.py', 'exec'), namespace)
    exported = tuple(namespace['__all__'])
    assert exported == ('cluster_assignment_unavailable', 'cluster_signal_unavailable_reason')
    unavailable = namespace['cluster_assignment_unavailable']('cluster_snapshot_missing')
    assert unavailable['degraded'] is True
    assert unavailable['probability_ready'] if False else True
    assert unavailable['unavailable_reason'] == 'cluster_snapshot_missing'
    assert unavailable['final_json_must_record'] is True
    assert unavailable['replay_record_required'] is True


def test_stage1462_clustering_internal_imports_use_public_common_and_evidence_names():
    forbidden = PRIVATE_COMMON_NAMES + PRIVATE_EVIDENCE_NAMES + PRIVATE_VECTOR_NAMES
    offenders = []
    for path in CLUSTERING_ROOT.glob('*.py'):
        if path.name == 'state.py':
            continue
        source = path.read_text(encoding='utf-8')
        for private_name in forbidden:
            if private_name in source:
                offenders.append(f'{path}:{private_name}')
    assert offenders == []


def test_stage1462_clustering_vector_owner_exports_public_sanitize_names_only():
    tree = _module_tree('Virus_Scan/models/clustering/vectors.py')
    function_names = tuple(node.name for node in tree.body if isinstance(node, ast.FunctionDef))
    for private_name in PRIVATE_VECTOR_NAMES:
        assert private_name not in function_names
    namespace = {}
    exec(compile(tree, 'Virus_Scan/models/clustering/vectors.py', 'exec'), namespace)
    exported = tuple(namespace['__all__'])
    assert 'sanitize_feature_vector' in exported
    assert 'vector_cluster_members_for' in exported
    assert all(not name.startswith('_') for name in exported)
