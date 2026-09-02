from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path



def test_model_api_no_longer_owns_profile_context_bridge_file():
    assert not Path('Virus_Scan/models/api/profile_context_contracts.py').exists()


def test_model_api_does_not_import_routing_context_identity():
    api_dir = Path('Virus_Scan/models/api')
    offenders = []
    for module in api_dir.glob('*.py'):
        text = module.read_text(encoding='utf-8')
        if 'Virus_Scan.routing.context_identity' in text or 'Virus_Scan.routing.context_identity_types' in text:
            offenders.append(str(module))
    assert offenders == []


def test_repository_profile_context_contract_is_the_single_profile_learning_context_boundary():
    source = read_python_file(Path('Virus_Scan/models/profiles/context.py'))
    assert 'from Virus_Scan.contracts.profile_context_identity import profile_learning_context_identity' in source
    assert 'Virus_Scan.models.api.profile_context_contracts' not in source
