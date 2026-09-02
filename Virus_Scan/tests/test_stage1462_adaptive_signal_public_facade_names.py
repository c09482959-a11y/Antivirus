from pathlib import Path
import ast

import Virus_Scan.models.api.adaptive_signals as adaptive_signals

ADAPTIVE_SIGNALS_PATH = Path('Virus_Scan/models/api/adaptive_signals.py')
FORBIDDEN_PRIVATE_ADAPTIVE_SIGNAL_NAMES = (
    '_adaptive_cluster_signal',
    '_context_cluster_quality',
    '_cluster_risk_score',
    '_cluster_risk_score_evidence',
    '_compute_graph_relationship_layer',
    '_get_graph_risk_enhanced',
    '_get_graph_risk_enhanced_evidence',
    '_adaptive_markov_signal',
    '_canonical_behavior_flow',
    '_compute_markov_features',
    '_adaptive_profile_signal',
    '_extension_profile_anomaly',
    '_coordinated_model_validation_signal',
    '_public_event_sequence',
    '_immutable_adaptive_signal',
    '_adaptive_unavailable',
    '_coordinated_validation_unavailable',
)


def _tree() -> ast.Module:
    return ast.parse(ADAPTIVE_SIGNALS_PATH.read_text(encoding='utf-8'))


def test_stage1462_adaptive_signals_facade_has_no_private_import_aliases_or_defs():
    offenders = []
    for node in _tree().body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local_name = alias.asname or alias.name
                if local_name.startswith('_'):
                    offenders.append(f'import:{node.lineno}:{local_name}')
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name.startswith('_'):
                offenders.append(f'def:{node.lineno}:{node.name}')
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.startswith('_') and target.id != '__all__':
                    offenders.append(f'assign:{node.lineno}:{target.id}')
    assert offenders == []


def test_stage1462_adaptive_signals_facade_removed_old_private_owner_aliases():
    for private_name in FORBIDDEN_PRIVATE_ADAPTIVE_SIGNAL_NAMES:
        assert private_name not in adaptive_signals.__dict__
    assert 'immutable_adaptive_signal' in adaptive_signals.__dict__
    assert 'public_adaptive_event_sequence' in adaptive_signals.__dict__


def test_stage1462_adaptive_signals_public_all_stays_narrow():
    exported = tuple(adaptive_signals.__all__)
    assert all(not name.startswith('_') for name in exported)
    assert 'adaptive_markov_signal' in exported
    assert 'adaptive_profile_signal' in exported
    assert 'adaptive_cluster_signal' in exported
    assert 'compute_markov_features' in exported
    assert 'cluster_risk_score_evidence' in exported
