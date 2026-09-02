"""Phase 4/12 regression tests for canonical runtime env parsing."""
from __future__ import annotations

from Virus_Scan.contracts.env_config import float_env, int_env
from Virus_Scan.runtime.config import ArchiveScanLimits, StageConcurrencyLimits
from Virus_Scan.runtime.resource_economics import ResourceEconomicsConfig
from Virus_Scan.runtime.telemetry import RuntimeTelemetry
from tests.support.env_override import temporary_environ


def test_env_config_float_contract_supports_unbounded_maximum():
    with temporary_environ({"UMIGE_TEST_FLOAT": "12.5"}):
        assert float_env("UMIGE_TEST_FLOAT", 1.0, 0.0, None) == 12.5
    with temporary_environ({"UMIGE_TEST_FLOAT": "bad"}):
        assert float_env("UMIGE_TEST_FLOAT", 2.0, 0.0, None) == 2.0


def test_runtime_config_and_economics_use_public_env_contract():
    with temporary_environ({"UMIGE_ARCHIVE_MAX_RATIO": "150.5", "UMIGE_MAX_ARCHIVE_EXPANSION_RATIO": "90.25"}):
        assert ArchiveScanLimits.from_env().max_decompression_ratio == 150.5
        assert ResourceEconomicsConfig.from_env().max_archive_expansion_ratio == 90.25
        assert StageConcurrencyLimits.from_env().archive >= 1


def test_runtime_telemetry_pressure_threshold_uses_public_float_contract():
    with temporary_environ({"UMIGE_TELEMETRY_PRESSURE_THRESHOLD": "0.42"}):
        assert RuntimeTelemetry().pressure_threshold == 0.42


def test_env_config_int_contract_bounds_values():
    with temporary_environ({"UMIGE_TEST_INT": "999"}):
        assert int_env("UMIGE_TEST_INT", 1, 0, 10) == 10
