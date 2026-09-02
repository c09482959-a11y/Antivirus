from __future__ import annotations

from Virus_Scan.models import profiles
from Virus_Scan.models.profiles import api as profile_api

_MARKOV_OWNER_NAMES = (
)


def test_stage1453_profiles_root_does_not_reexport_markov_owner_api():
    assert sorted(set(_MARKOV_OWNER_NAMES) & set(profiles.__all__)) == []
    for name in _MARKOV_OWNER_NAMES:
        assert not hasattr(profiles, name)


def test_stage1453_profile_api_public_all_does_not_advertise_markov_owner_api():
    assert sorted(set(_MARKOV_OWNER_NAMES) & set(profile_api.__all__)) == []
    # Profile-owned flow construction remains available; raw Markov computation stays under Markov contracts.
    assert "canonical_behavior_flow_from_sources" in profile_api.__all__
