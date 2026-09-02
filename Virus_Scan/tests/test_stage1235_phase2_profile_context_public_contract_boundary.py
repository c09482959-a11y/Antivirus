from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.contracts.profile_context_identity import profile_learning_context_identity
from Virus_Scan.models import profiles
from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES
from Virus_Scan.routing.context_identity import classify_engine_context



def test_profiles_consumes_repository_contract_not_routing_or_model_bridge():
    source = read_python_file(Path('Virus_Scan/models/profiles/context.py'))
    assert 'from Virus_Scan.routing.context_identity import classify_engine_context' not in source
    assert 'import Virus_Scan.routing.context_identity' not in source
    assert 'Virus_Scan.models.api.profile_context_contracts' not in source
    assert 'from Virus_Scan.contracts.profile_context_identity import profile_learning_context_identity' in source
    assert 'profile_learning_context_identity(' in source


def test_profile_context_contract_matches_canonical_routing_identity(tmp_path):
    sample = tmp_path / 'game' / 'script.rpy'
    sample.parent.mkdir()
    sample.write_text('label start:\n    return\n', encoding='utf-8')

    public_identity = profile_learning_context_identity(sample, container_root=sample.parent, trusted_benign=True)
    routing_identity = classify_engine_context(sample, container_root=sample.parent, trusted_benign=True)

    assert public_identity == routing_identity
    assert isinstance(public_identity.sniffed_embedded_types, tuple)
    assert isinstance(public_identity.baseline_lookup_order, tuple)
    assert public_identity.baseline_lookup_order[0] == public_identity.baseline_key


def test_contextual_profile_learning_policy_uses_public_contract(tmp_path):
    sample = tmp_path / 'game' / 'data.win'
    sample.parent.mkdir()
    sample.write_bytes(b'')

    identity = profiles.contextual_profile_learning_policy(sample, trusted_benign=True, degraded=False)

    assert identity.baseline_key
    assert isinstance(identity.blocked_baseline_keys, tuple)
    assert isinstance(identity.fingerprint_evidence, tuple)


def test_profile_context_contract_is_not_registered_as_model_bootstrap_bridge():
    assert 'Virus_Scan.models.api.profile_context_contracts' not in MODEL_BOOTSTRAP_MODULE_NAMES
    assert all('profile_context_contracts' not in name for name in MODEL_BOOTSTRAP_MODULE_NAMES)
