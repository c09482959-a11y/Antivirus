import inspect

from Virus_Scan.detection.scoring.adaptive import log_odds_fusion
from Virus_Scan.detection.scoring.adaptive import model_score
from Virus_Scan.detection.scoring.yara import context_evidence
from Virus_Scan.tests.support.canonical_yara_fixtures import canonical_test_yara_result
from Virus_Scan.models.profiles import api as profile_api
from Virus_Scan.models.profiles import commit as profile_commit
from Virus_Scan.models.profiles import persistence as profile_persistence


def test_stage1157_adaptive_model_score_uses_public_probability_contracts():
    source = inspect.getsource(model_score)
    fusion_source = inspect.getsource(log_odds_fusion)

    assert "from Virus_Scan.core.logging import _" not in source
    assert "from Virus_Scan.reporting.summary import _layer_probability_summary" not in source
    assert "from Virus_Scan.utils.probability import (" in fusion_source
    assert model_score.score_to_probability(50.0) > 0.0
    assert not hasattr(model_score, "_score_to_probability")


def test_stage1157_yara_scoring_exports_public_nonprobability_context():
    assert hasattr(context_evidence, "generic_yara_evidence_context")
    assert not hasattr(context_evidence, "yara_weight")
    context = context_evidence.generic_yara_evidence_context(canonical_test_yara_result())
    assert context.probability_authority is False


def test_stage1157_profiles_use_public_runtime_and_learning_contracts():
    api_source = inspect.getsource(profile_api)
    commit_source = inspect.getsource(profile_commit)
    persistence_source = inspect.getsource(profile_persistence)

    assert "from Virus_Scan.core.paths import _umige_runtime_base_dir" not in api_source
    assert "from Virus_Scan.models.learning import _learning_guard" not in api_source
    assert "from Virus_Scan.core.paths" not in api_source
    assert "from Virus_Scan.core.paths" not in persistence_source
    assert "from Virus_Scan.runtime.resource_paths import program_root" in persistence_source
    assert "str(program_root())" in persistence_source
    assert "_runtime_program_root" not in persistence_source
    assert "with learning_guard() as entered:" in commit_source
