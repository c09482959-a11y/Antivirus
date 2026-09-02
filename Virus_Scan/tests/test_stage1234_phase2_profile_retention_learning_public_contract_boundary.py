from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.models import learning as learning_owner
from Virus_Scan.models import profiles
import Virus_Scan.models.api as model_api
from Virus_Scan.models.api import learning_context_contracts, profile_retention_contracts
from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES
from Virus_Scan.models import retention as retention_owner



def test_stage1234_profiles_use_public_learning_and_retention_contracts() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/api.py"))

    assert "from Virus_Scan.models.learning import" not in source
    assert "from Virus_Scan.models.retention import" not in source
    assert "from Virus_Scan.models.api.learning_context_contracts import learning_guard" in source
    assert "from Virus_Scan.models.api.profile_retention_contracts import" in source


def test_stage1234_learning_guard_contract_preserves_single_owner() -> None:
    assert learning_context_contracts.learning_guard is learning_owner.learning_guard
    assert profiles.learning_guard is learning_owner.learning_guard


def test_stage1234_profile_retention_contract_preserves_single_owner_functions() -> None:
    assert (
        profile_retention_contracts.prune_engine_profile_for_retention
        is not retention_owner.prune_engine_profile_for_retention
    )
    profile = {"extension_baselines": {}, "model_state": {}}
    returned = profile_retention_contracts.prune_engine_profile_for_retention(profile)
    assert returned is profile
    assert "retention" in profile


def test_stage1234_profile_retention_contract_exports_are_narrow() -> None:
    assert set(profile_retention_contracts.__all__) == {
        "prune_engine_profile_for_retention",
        "prune_extension_baseline_for_retention",
        "prune_staged_benign_store",
    }
    assert learning_context_contracts.__all__ == ("learning_guard",)


def test_stage1234_new_public_contracts_are_bootstrap_visible() -> None:
    assert "learning_context_contracts" in model_api.__all__
    assert "profile_retention_contracts" in model_api.__all__
    assert "Virus_Scan.models.api.learning_context_contracts" in MODEL_BOOTSTRAP_MODULE_NAMES
    assert "Virus_Scan.models.api.profile_retention_contracts" in MODEL_BOOTSTRAP_MODULE_NAMES
