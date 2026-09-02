from __future__ import annotations

import math

from Virus_Scan.routing import engine_fingerprints, engine_target_detection, magic_extension_tags
from Virus_Scan.routing.context_container_fingerprints import direct_container_fingerprint
from Virus_Scan.routing.extension_outcome import RouteScanOutcome


class _HostileText:
    def __str__(self) -> str:  # pragma: no cover - must not be invoked
        raise AssertionError("hostile __str__ executed")


class _HostileMapping(dict):
    def items(self):  # pragma: no cover - must not be invoked
        raise AssertionError("hostile mapping items executed")


class _HostileFloat(float):
    def is_integer(self) -> bool:  # pragma: no cover - must not be invoked
        raise AssertionError("hostile float subclass method executed")


def test_stage2081_route_outcome_materializes_constructor_boundaries_without_hooks() -> None:
    outcome = RouteScanOutcome(tags=["safe", _HostileText(), "kept"], suspicious=_HostileText(), identity=_HostileMapping())

    assert outcome.tags == ("safe", "kept")
    assert outcome.suspicious is False
    assert dict(outcome.identity) == {}
    assert list(outcome) == [["safe", "kept"], False]


def test_stage2081_engine_fingerprint_mapping_items_are_strictly_typed(tmp_path) -> None:
    direct = engine_fingerprints.score_direct_container_directory("Managed")
    assert direct["unity"].engine == "unity"
    assert "direct_dir:managed" in direct["unity"].evidence

    selected = engine_fingerprints.choose_engine(_HostileMapping())
    assert selected.engine == "other"
    assert selected.evidence == ("no_engine_fingerprint",)

    assert direct_container_fingerprint(tmp_path).engine == "other"


def test_stage2081_magic_and_target_helpers_use_explicit_materialization() -> None:
    record = magic_extension_tags.rpgm_passive_recovery_record(
        ".rpgmvp",
        "image",
        "rpgm_mv_encrypted_asset",
        ("rpgm_encrypted_asset", "rpgm_encrypted_image"),
    )
    assert record["recovered"] is True
    assert record["unavailable_reasons"] == {}
    assert magic_extension_tags._exact_magic_score(2.0) == 2
    assert magic_extension_tags._exact_magic_score(float("nan")) == 0
    assert magic_extension_tags._exact_magic_score(_HostileFloat(3.0)) == 0
    assert math.isfinite(magic_extension_tags._exact_magic_score(4.0))

    assert engine_target_detection._target_path(_HostileText()) is None
