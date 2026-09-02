"""Phase 13 actual YARA engine integration for the supplied rule archives."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("yara")

from Virus_Scan.detection.attack.yara_alignment import project_yara_observations
from Virus_Scan.runtime.api import release_yara_runtime, yara_rules_state
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.loader import load_yara_rules, load_yaralight_rules
from Virus_Scan.yara.match import yara_scan

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_CORE_ARCHIVE = _REPOSITORY_ROOT / "Yara" / "yara-forge-rules-core.zip"
_EXTENDED_ARCHIVE = _REPOSITORY_ROOT / "Yara" / "yara-forge-rules-extended.zip"
_CORE_SHA256 = "3ad85d8518e5e968d930c93dadae9dcd7d215d0911d8d8f02717f15922c8529f"
_EXTENDED_SHA256 = "756bd295a87603d78f1c879ecb7d217c91c1bcb03461c34e604fa20a4a0acae5"
_REPOSITORY_DIGEST = "96da129230304ea566cfa7dc7f0bf94da7f6b01bb41fad810943ff1d98a840b3"

_FIXTURES = (
    (
        "lsass.pe.fixture",
        b"MZ" + b"\x00" * 62
        + b"lsass dumped successfully!\x00Got lsass.exe PID:\x00SAFE INERT FIXTURE\n",
        "DITEKSHEN_INDICATOR_TOOL_PWS_LSASS_Createminidump",
    ),
    (
        "ps1.txt",
        b"# SAFE INERT TEXT FIXTURE - .txt, NOT EXECUTABLE\n"
        b"[AppDomain]::CurrentDomain.DefineDynamicAssembly\n"
        b"InMemoryModule\nMyDelegateType\n"
        b"New-Object System.Reflection.AssemblyName('ReflectedDelegate')\n"
        b"[Byte[]]$var_code = [System.Convert]::FromBase64String(\n"
        b"[IntPtr]::size -eq 8\nMandatory = $True\n",
        "GCTI_Cobaltstrike_Resources_Template_X64_Ps1_V3_0_To_V4_X_Excluding_3_12_3_13",
    ),
    (
        "vba.txt",
        b"SAFE INERT TEXT FIXTURE - NOT VBA EXECUTABLE\n"
        b"Function CreateStuff Lib \"kernel32\" Alias \"CreateRemoteThread\"\n"
        b"Function AllocStuff Lib \"kernel32\" Alias \"VirtualAllocEx\"\n"
        b"Function WriteStuff Lib \"kernel32\" Alias \"WriteProcessMemory\"\n"
        b"Function RunStuff Lib \"kernel32\" Alias \"CreateProcessA\"\n"
        b"Dim rwxpage As Long\n"
        b"RunStuff(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, "
        b"ByVal 0&, sNull, sInfo, pInfo)\n"
        b"AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)\n",
        "GCTI_Cobaltstrike_Resources_Template_X86_Vba_V3_8_To_V4_X",
    ),
)


def _write_fixtures(root: Path) -> tuple[tuple[Path, str], ...]:
    written: list[tuple[Path, str]] = []
    for name, payload, expected_rule in _FIXTURES:
        path = root / name
        path.write_bytes(payload)
        written.append((path, expected_rule))
    return tuple(written)


def _assert_engine_handoff(
    snapshot: object,
    fixtures: tuple[tuple[Path, str], ...],
    package: str,
) -> None:
    for path, expected_rule in fixtures:
        result = yara_scan(path, compiled_rules=snapshot)
        assert result.status == "complete"
        assert result.package_kind == package
        assert result.total_match_count >= 1
        matching = tuple(
            hit for hit in result.hits
            if hit.rule_identity.rule_name == expected_rule
        )
        assert len(matching) == 1
        hit = matching[0]
        assert hit.verified is True
        assert hit.rule_identity.package_kind == package
        observations = project_yara_observations(
            result,
            platform="windows",
            repository_digest=_REPOSITORY_DIGEST,
        )
        assert len(observations) == 1
        assert observations[0].root_observation_id == hit.root_observation_id
        assert observations[0].directness == "context"
        assert observations[0].confidence == 0.0


def test_supplied_core_and_extended_archives_compile_and_project_with_real_engine(
    tmp_path: Path,
) -> None:
    fixtures = _write_fixtures(tmp_path)
    config = YaraConfig(
        full_expected_sha256=_EXTENDED_SHA256,
        light_expected_sha256=_CORE_SHA256,
    )
    try:
        core_attempt = load_yaralight_rules(
            str(_CORE_ARCHIVE),
            auto_download=False,
            use_cache=False,
            config=config,
            allow_cache_write=False,
        )
        assert core_attempt.load_result.ready is True
        assert core_attempt.source is not None
        assert core_attempt.source.package_kind == "core"
        _assert_engine_handoff(
            yara_rules_state().light_snapshot(), fixtures, "core",
        )

        extended_attempt = load_yara_rules(
            str(_EXTENDED_ARCHIVE),
            auto_download=False,
            use_cache=False,
            config=config,
            allow_cache_write=False,
        )
        assert extended_attempt.load_result.ready is True
        assert extended_attempt.source is not None
        assert extended_attempt.source.package_kind == "extended"
        _assert_engine_handoff(
            yara_rules_state().primary_snapshot(), fixtures, "extended",
        )
    finally:
        release_yara_runtime()
