import ast
from pathlib import Path

from Virus_Scan.detection.scoring.adaptive import evidence_projection
from Virus_Scan.detection.scoring.adaptive import model_inputs

MODEL_INPUTS = Path('Virus_Scan/detection/scoring/adaptive/model_inputs.py')
EVIDENCE_PROJECTION = Path('Virus_Scan/detection/scoring/adaptive/evidence_projection.py')
MODEL_SCORE = Path('Virus_Scan/detection/scoring/adaptive/model_score.py')


def _tree(path):
    return ast.parse(path.read_text(encoding='utf-8'))


def _imported_names(path):
    names = []
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.ImportFrom):
            names.extend(alias.asname or alias.name for alias in node.names)
    return tuple(names)


def _defined_function_names(path):
    return tuple(
        node.name
        for node in ast.walk(_tree(path))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def test_stage1459_adaptive_model_inputs_publish_owner_names_only():
    assert model_inputs.__all__ == (
        'cluster_probability_feature',
        'graph_chain_probability_from_layer',
    )
    assert not hasattr(model_inputs, '_cluster_probability_feature')
    assert not hasattr(model_inputs, '_graph_chain_probability_from_layer')
    assert 'cluster_probability_feature' in _defined_function_names(MODEL_INPUTS)
    assert 'graph_chain_probability_from_layer' in _defined_function_names(MODEL_INPUTS)


def test_stage1459_adaptive_consumers_do_not_import_private_model_input_helpers():
    forbidden = {
        '_cluster_probability_feature',
        '_graph_chain_probability_from_layer',
    }

    for path in (EVIDENCE_PROJECTION, MODEL_SCORE):
        assert not (forbidden & set(_imported_names(path)))
        text = path.read_text(encoding='utf-8')
        for name in forbidden:
            assert name not in text


def test_stage1459_graph_chain_probability_evidence_remains_explicit_for_unready_layer():
    probability, reason = model_inputs.graph_chain_probability_from_layer({'ready': False, 'score': 75})

    assert probability == 0.0
    assert reason == 'graph_relationship_layer_not_ready'


def test_stage1459_probability_feature_bundle_has_public_owner_name():
    assert 'probability_feature_bundle' in evidence_projection.__all__
    assert 'build_probability_features' in evidence_projection.__all__
    assert not hasattr(evidence_projection, '_probability_feature_bundle')
    assert 'probability_feature_bundle' in _defined_function_names(EVIDENCE_PROJECTION)


def test_stage1459_probability_feature_consumers_do_not_import_private_bundle_helper():
    for path in (MODEL_SCORE, Path('Virus_Scan/detection/scoring/adaptive/log_odds_fusion.py')):
        assert '_probability_feature_bundle' not in path.read_text(encoding='utf-8')
        assert 'probability_feature_bundle' in _imported_names(path)
