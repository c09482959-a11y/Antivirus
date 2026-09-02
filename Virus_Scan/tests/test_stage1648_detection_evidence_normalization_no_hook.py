from Virus_Scan.detection.evidence.normalization import (
    confidence_decay,
    correlation_ceiling,
    dedupe_correlated_evidence,
    summarize_evidence_families,
)


class HostileText:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook executed")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("repr hook executed")


class HostileIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook executed")


class HostileNumeric:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook executed")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("float hook executed")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("int hook executed")


class HostileMapping(dict):
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook executed")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("items hook executed")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("get hook executed")


def test_stage1648_evidence_family_tags_reject_hostile_values_without_hooks():
    HostileText.touched = 0
    HostileIterable.touched = 0

    assert summarize_evidence_families(["powershell", HostileText(), "http_download"]) == {
        "execution": ["powershell"],
        "networking": ["http_download"],
    }
    assert summarize_evidence_families(HostileIterable()) == {}
    assert HostileText.touched == 0
    assert HostileIterable.touched == 0


def test_stage1648_correlation_and_decay_reject_hostile_numeric_hooks():
    HostileNumeric.touched = 0

    ceiling = correlation_ceiling(
        ["memory_write", "token_secret_access"],
        base_score=HostileNumeric(),
        lineage_depth=HostileNumeric(),
        replay_depth=HostileNumeric(),
    )
    decayed = confidence_decay(
        HostileNumeric(),
        lineage_distance=HostileNumeric(),
        replay_depth=HostileNumeric(),
        time_steps=HostileNumeric(),
    )

    assert ceiling["high_anchor"] is True
    assert ceiling["score"] == 92.0
    assert decayed == 0.0
    assert HostileNumeric.touched == 0


def test_stage1648_dedupe_correlated_evidence_uses_no_hook_mapping_reads():
    HostileMapping.touched = 0
    HostileText.touched = 0
    first = {"family": "execution", "source": "alpha", "origin": "scan", "detail": HostileText()}
    duplicate = {"family": "execution", "source": "alpha", "origin": "scan", "detail": "duplicate"}
    second = {"family": "networking", "source": "beta", "origin": "scan"}
    hostile = HostileMapping(family="credential", source="gamma", origin="scan")

    result = dedupe_correlated_evidence([first, duplicate, second, hostile, HostileText()])

    assert len(result) == 2
    assert result[0]["family"] == "execution"
    assert result[0]["detail"]["unavailable_reason"] == "non_materializable_detection_evidence_record_value"
    assert result[1] == {"family": "networking", "source": "beta", "origin": "scan"}
    assert HostileMapping.touched == 0
    assert HostileText.touched == 0
