from __future__ import annotations

import os
from types import MappingProxyType

import pytest

from Virus_Scan.runtime.event_contracts import (
    EventContract,
    event_contract_snapshot,
    get_event_contract,
    validate_event_contract,
)
from Virus_Scan.runtime.resource_economics import (
    ArchiveEcosystemScore,
    ExtractionEconomics,
    RepricingInertiaConfig,
    ResourceEconomicsConfig,
    WorkComplexitySignal,
    adaptive_reprice_cost,
    apply_repricing_inertia,
    archive_complexity_score,
    archive_ecosystem_score,
    confidence_inertia,
    cross_domain_pressure_budget,
    extension_cost,
    queue_cost,
)


class temporary_env:
    def __init__(self, **updates: str) -> None:
        self._updates = updates
        self._saved: dict[str, str | None] = {}

    def __enter__(self) -> None:
        for name, value in self._updates.items():
            self._saved[name] = os.environ.get(name)
            os.environ[name] = value

    def __exit__(self, exc_type, exc, tb) -> None:
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_stage946_event_contracts_validate_required_fields_and_unknown_events_fail_closed() -> None:
    contract, ok, reason = validate_event_contract("runtime", "exports_registered", {"count": 3})
    assert contract.key == "runtime:exports_registered"
    assert ok is True
    assert reason == "ok"

    contract, ok, reason = validate_event_contract("runtime", "exports_registered", {})
    assert contract.required_fields == ("count",)
    assert ok is False
    assert reason == "missing_fields:count"

    with pytest.raises(KeyError, match="unregistered event contract"):
        get_event_contract("runtime", "unowned_dynamic_event")


def test_stage946_event_contract_snapshot_is_sorted_and_read_only() -> None:
    snapshot = event_contract_snapshot()

    assert isinstance(snapshot, MappingProxyType)
    assert list(snapshot) == sorted(snapshot)
    assert snapshot["governance:circuit_breaker"]["severity"] == "critical"
    assert snapshot["semantic:influence_budget"]["required_fields"] == ["source", "target", "kind"]

    with pytest.raises(TypeError):
        snapshot["runtime:event"] = {}  # type: ignore[index]


def test_stage946_event_contract_value_object_reports_key_and_missing_fields_stably() -> None:
    contract = EventContract("scheduler", "unit", "scheduler", required_fields=("b", "a"))

    assert contract.key == "scheduler:unit"
    assert contract.validate({"a": 1, "b": 2}) == (True, "ok")
    assert contract.validate({"b": 2}) == (False, "missing_fields:a")


def test_stage946_resource_economics_config_reads_bounded_env_values() -> None:
    with temporary_env(
        UMIGE_MAX_ARCHIVE_FANOUT_SCORE="0",
        UMIGE_MAX_ARCHIVE_EXPANSION_RATIO="0.25",
        UMIGE_MAX_PENDING_EXPANSION_BYTES="512",
        UMIGE_MAX_WORKLOAD_COST="-9",
        UMIGE_MAX_QUEUE_COST_WINDOW="bad-int",
    ):
        config = ResourceEconomicsConfig.from_env()

    assert config.max_archive_fanout_score == 1
    assert config.max_archive_expansion_ratio == 1.0
    assert config.max_pending_expansion_bytes == 1024
    assert config.max_workload_cost == 1
    assert config.max_queue_cost_window == ResourceEconomicsConfig.max_queue_cost_window
    assert config.env_mapping()["UMIGE_MAX_WORKLOAD_COST"] == "1"


def test_stage946_extraction_economics_enforces_bytes_ratio_and_fanout_limits() -> None:
    byte_limited = ExtractionEconomics(ResourceEconomicsConfig(max_pending_expansion_bytes=10_000))
    with pytest.raises(RuntimeError, match="archive_pending_expansion_byte_budget"):
        byte_limited.observe_member(compressed_size=10, extracted_size=10_001)

    ratio_limited = ExtractionEconomics(ResourceEconomicsConfig(max_archive_expansion_ratio=2.0, max_pending_expansion_bytes=10_000_000))
    with pytest.raises(RuntimeError, match="archive_cumulative_expansion_ratio"):
        ratio_limited.observe_member(compressed_size=10, extracted_size=25)

    fanout_limited = ExtractionEconomics(ResourceEconomicsConfig(max_archive_fanout_score=20, max_pending_expansion_bytes=10_000_000))
    with pytest.raises(RuntimeError, match="archive_fanout_score_limit"):
        fanout_limited.observe_member(compressed_size=100, extracted_size=100, is_archive=True)


def test_stage946_extension_queue_and_adaptive_costs_use_runtime_complexity_not_threat_tags(tmp_path) -> None:
    archive = tmp_path / "nested.rpa"
    archive.write_bytes(b"x" * (2 * 1024 * 1024))
    script = tmp_path / "game.rpy"
    script.write_text("label start: pass", encoding="utf-8")

    assert extension_cost(archive) == 250
    assert extension_cost(script) == 70
    assert queue_cost([archive, script]) == 322

    with temporary_env(UMIGE_MAX_WORKLOAD_COST="600"):
        cost = adaptive_reprice_cost(
            archive,
            discovered_members=100,
            discovered_bytes=300 * 1024 * 1024,
            complexity_signals=(WorkComplexitySignal("custom_runtime", 123), "nested_archive", "ignored_threat_tag"),
        )

    assert cost == 600


def test_stage946_archive_complexity_and_ecosystem_scores_are_bounded_and_deterministic() -> None:
    complexity = archive_complexity_score(
        members=10,
        compressed_bytes=1024,
        extracted_bytes=10 * 1024,
        nested_archives=2,
        corrupt_members=1,
        compression_kinds=3,
    )
    assert complexity.expansion_ratio == 10.0
    assert complexity.score == 20 + 80 + 35 + 50 + 0 + 50

    ecosystem = archive_ecosystem_score(
        members=100,
        compressed_bytes=1,
        extracted_bytes=10_000_000,
        depth=4,
        nested_archives=30,
        corrupt_members=50,
        distinct_extensions=40,
    )
    assert isinstance(ecosystem, ArchiveEcosystemScore)
    assert ecosystem.metadata_density == 10.0
    assert ecosystem.decompression_unpredictability == 1.0
    assert ecosystem.score <= 5000


def test_stage946_inertia_and_pressure_guards_bound_runtime_feedback() -> None:
    assert confidence_inertia(50, 90, max_step=12) == 62
    assert confidence_inertia(50, 10, max_step=12) == 38
    assert confidence_inertia(5, -100, max_step=20, floor=0) == 0

    assert apply_repricing_inertia(100, 1000, config=RepricingInertiaConfig(max_step=50, smoothing=1.0)) == 150
    assert apply_repricing_inertia(1000, 100, config=RepricingInertiaConfig(max_step=50, smoothing=1.0)) == 950
    assert apply_repricing_inertia(None, 17, config=RepricingInertiaConfig(max_step=50, smoothing=0.5)) == 17

    assert cross_domain_pressure_budget(0.2, 0.3, budget=0.6) == (True, 0.5)
    assert cross_domain_pressure_budget(0.7, 0.3, budget=0.6) == (False, 1.0)
    with pytest.raises(ValueError, match="invalid pressure value count: 1"):
        cross_domain_pressure_budget(0.1, "bad")  # type: ignore[arg-type]
