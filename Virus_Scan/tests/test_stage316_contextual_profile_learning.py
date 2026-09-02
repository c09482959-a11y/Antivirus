from __future__ import annotations

from pathlib import Path

from Virus_Scan.models.profiles import contextual_profile_learning_policy, get_extension_baseline, record_learning_rejection, should_learn_scan_result
from Virus_Scan.models.profiles.request_contracts import ProfileLearningGateRequest
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles


def _mz(path: Path, marker: bytes = b'') -> None:
    path.write_bytes(b'MZ' + b'\x00' * 128 + marker)


def test_stage316_profile_learning_blocks_renpy_container_unity_dll(tmp_path: Path) -> None:
    root = tmp_path / 'renpy_game'
    (root / 'game').mkdir(parents=True)
    (root / 'game' / 'script.rpy').write_text('label start:\n    return\n', encoding='utf-8')
    dll = root / 'Assembly-CSharp.dll'
    _mz(dll, b'BSJB mscorlib UnityEngine Assembly-CSharp')

    allowed, reason, validation = should_learn_scan_result(ProfileLearningGateRequest('renpy', dll, [], risk=0.0, verdict='clean'))

    assert allowed is False
    assert reason == 'cross-engine artifact requires trusted benign allowlist before learning'
    ctx = validation['contextual_engine_identity']
    assert ctx['container_engine'] == 'renpy'
    assert ctx['artifact_engine'] == 'unity'
    assert ctx['cross_engine_artifact'] is True
    assert ctx['learning_allowed'] is False
    assert 'renpy/.dll' in ctx['blocked_baseline_keys']


def test_stage316_profile_baseline_key_uses_contextual_rejection_bucket(tmp_path: Path) -> None:
    bind_profile_database(tmp_path)
    ensure_authoritative_engine_profiles()
    root = tmp_path / 'renpy_game'
    (root / 'game').mkdir(parents=True)
    (root / 'game' / 'script.rpy').write_text('label start:\n    return\n', encoding='utf-8')
    dll = root / 'Assembly-CSharp.dll'
    _mz(dll, b'BSJB mscorlib UnityEngine Assembly-CSharp')

    recorded = record_learning_rejection('renpy', dll, 'cross-engine artifact requires trusted benign allowlist before learning')
    baseline = get_extension_baseline('renpy', dll)

    assert recorded['extension'] == 'renpy::unity::.dll::mono_dotnet_assembly'
    assert baseline['learning_gate']['accepted'] == 0
    assert baseline['learning_gate']['rejected'] == 1


def test_stage316_clean_same_context_file_can_select_artifact_extension_baseline(tmp_path: Path) -> None:
    root = tmp_path / 'renpy_game'
    (root / 'game').mkdir(parents=True)
    rpy = root / 'game' / 'script.rpy'
    rpy.write_text('label start:\n    return\n', encoding='utf-8')

    ctx = contextual_profile_learning_policy(rpy, trusted_benign=True)

    assert ctx.container_engine == 'renpy'
    assert ctx.artifact_engine == 'renpy'
    assert ctx.learning_allowed is True
    assert ctx.learning_baseline_key == 'renpy/.rpy'
