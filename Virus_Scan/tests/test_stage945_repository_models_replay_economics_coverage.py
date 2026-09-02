from __future__ import annotations

import hashlib
import os

from Virus_Scan.models.replay_economics import (
    ReplayEconomicsConfig,
    replay_compress_metadata,
    replay_should_retain,
)


def test_replay_economics_config_reads_env_with_clamped_numeric_policy():
    saved = {name: os.environ.get(name) for name in (
        "UMIGE_REPLAY_MAX_METADATA_RECORDS",
        "UMIGE_REPLAY_SAMPLE_MODULO",
        "UMIGE_REPLAY_KEEP_DIVERGENCE",
    )}
    try:
        os.environ["UMIGE_REPLAY_MAX_METADATA_RECORDS"] = "0"
        os.environ["UMIGE_REPLAY_SAMPLE_MODULO"] = "-7"
        os.environ["UMIGE_REPLAY_KEEP_DIVERGENCE"] = "false"

        config = ReplayEconomicsConfig.from_env()

        assert config.max_metadata_records == 1
        assert config.sample_modulo == 1
        assert config.divergence_always_keep is False
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_replay_retention_keeps_divergence_high_score_and_deterministic_samples():
    rare_sample_config = ReplayEconomicsConfig(sample_modulo=10_000, divergence_always_keep=True)
    assert replay_should_retain({"replay_divergence": True}, index=1, config=rare_sample_config) is True
    assert replay_should_retain({"score": 25.0}, index=1, config=rare_sample_config) is True

    always_sample_config = ReplayEconomicsConfig(sample_modulo=1, divergence_always_keep=False)
    assert replay_should_retain({"path": "sample.bin", "score": 0}, index=123, config=always_sample_config) is True

    modulo = 97
    path = "deterministic/sample.bin"
    expected = int(hashlib.sha1(path.encode("utf-8", "ignore")).hexdigest()[:8], 16) % modulo == 0
    deterministic_config = ReplayEconomicsConfig(sample_modulo=modulo, divergence_always_keep=False)
    assert replay_should_retain({"path": path, "score": 0}, index=0, config=deterministic_config) is expected


def test_replay_metadata_compression_drops_heavy_fields_and_bounds_nested_shapes():
    raw = {
        "baseline": {"large": True},
        "raw": "remove me",
        "strings_blob": "remove me",
        "decoded_strings": ["remove me"],
        "kept": "x" * 550,
        "nested": list(range(40)),
        **{f"k{i}": i for i in range(40)},
    }

    compressed = replay_compress_metadata(raw)

    assert "baseline" not in compressed
    assert "raw" not in compressed
    assert "strings_blob" not in compressed
    assert "decoded_strings" not in compressed
    assert compressed["kept"].endswith("...<truncated>")
    assert len(compressed["nested"]) == 33
    assert compressed["nested"][-1] == {"truncated": True}
    assert compressed["truncated"] is True
    assert len(compressed) <= 33
