import inspect

from Virus_Scan.models import learning as learning_owner
from Virus_Scan.models.profiles import api as profile_api
from Virus_Scan.models.profiles import commit as profile_commit


def test_stage1128_profiles_do_not_own_learning_reentry_state():
    source = inspect.getsource(profile_commit)

    assert "_LEARNING_REENTRY_STATE =" not in source
    assert "def _learning_in_progress" not in source
    assert "with learning_guard() as entered:" in source
    assert "from Virus_Scan.models.learning import _learning_guard" not in source


def test_stage1128_learning_reentry_state_is_model_learning_owned():
    owner_source = inspect.getsource(learning_owner)

    assert "_LEARNING_REENTRY_STATE = threading.local()" in owner_source
    assert hasattr(learning_owner, "learning_guard")
    assert not hasattr(profile_api, "_learning_guard")
    assert profile_commit.learning_guard is learning_owner.learning_guard
