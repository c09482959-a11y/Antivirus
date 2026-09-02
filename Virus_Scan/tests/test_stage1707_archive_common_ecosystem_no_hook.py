from Virus_Scan.scanners.archives.common import extract_methods, rarity_multiplier_for_probability
from Virus_Scan.scanners.archives.ecosystem import (
    ArchiveEcosystemGateRequest,
    apply_ecosystem_gate,
    archive_ecosystem_inputs,
)
from Virus_Scan.scanners.config.loader import load_archive_policy_snapshot


class HostileText:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("text truthiness hook executed")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("text string hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("text repr hook executed")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("text format hook executed")


class HostileNumber:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("numeric truthiness hook executed")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("numeric int hook executed")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("numeric float hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("numeric repr hook executed")


class HostileNames:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("names iteration hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("names truthiness hook executed")


class HostileBucket:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bucket truthiness hook executed")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("bucket string hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("bucket repr hook executed")

    def __hash__(self):
        type(self).touched += 1
        raise RuntimeError("bucket hash hook executed")


def _reset_hostile_state():
    HostileText.touched = 0
    HostileNumber.touched = 0
    HostileNames.touched = 0
    HostileBucket.touched = 0


def _assert_no_hostile_hooks():
    assert HostileText.touched == 0
    assert HostileNumber.touched == 0
    assert HostileNames.touched == 0
    assert HostileBucket.touched == 0


def test_extract_methods_rejects_hostile_text_without_hooks_and_records_reason():
    _reset_hostile_state()

    result = extract_methods(HostileText())

    _assert_no_hostile_hooks()
    assert result == {"archive_methods_text_unsafe": "archive_methods_text_unsafe"}


def test_extract_methods_preserves_exact_text_behavior():
    source = "public void Run() {\n    DoThing();\n}\n"

    result = extract_methods(source)

    assert "public void Run() {" in result
    assert "DoThing();" in result["public void Run() {"]


def test_archive_ecosystem_inputs_rejects_hostile_names_and_numbers_without_hooks():
    _reset_hostile_state()

    result = archive_ecosystem_inputs(
        members=HostileNumber(),
        compressed_bytes=HostileNumber(),
        extracted_bytes=HostileNumber(),
        depth=HostileNumber(),
        names=HostileNames(),
    )

    _assert_no_hostile_hooks()
    assert result["members"] == 0
    assert result["compressed_bytes"] == 0
    assert result["extracted_bytes"] == 0
    assert result["depth"] == 0
    assert result["nested_archives"] == 0
    assert result["distinct_extensions"] == 1
    assert result["corrupt_members"] == 5


def test_archive_ecosystem_inputs_rejects_hostile_member_names_without_hooks():
    _reset_hostile_state()

    result = archive_ecosystem_inputs(
        members=3,
        compressed_bytes=30,
        extracted_bytes=60,
        depth=2,
        names=("nested.zip", HostileText(), "script.rpy"),
    )

    _assert_no_hostile_hooks()
    assert result["members"] == 3
    assert result["nested_archives"] == 1
    assert result["distinct_extensions"] == 2
    assert result["corrupt_members"] == 1


def test_archive_ecosystem_inputs_preserves_exact_primitive_behavior():
    result = archive_ecosystem_inputs(
        members=4,
        compressed_bytes=100,
        extracted_bytes=200,
        depth=1,
        names=("a.zip", "b.tar", "c.txt", "no_extension"),
    )

    assert result == {
        "members": 4,
        "compressed_bytes": 100,
        "extracted_bytes": 200,
        "depth": 1,
        "nested_archives": 2,
        "corrupt_members": 0,
        "distinct_extensions": 4,
    }


def test_rarity_multiplier_rejects_hostile_numeric_and_bucket_inputs_without_hooks():
    _reset_hostile_state()
    snapshot = load_archive_policy_snapshot()

    result = rarity_multiplier_for_probability(
        HostileNumber(),
        risk=HostileNumber(),
        bucket=HostileBucket(),
    )

    _assert_no_hostile_hooks()
    assert result == snapshot.rarity_high_risk_multiplier


def test_rarity_multiplier_preserves_exact_primitive_behavior():
    snapshot = load_archive_policy_snapshot()

    assert rarity_multiplier_for_probability(0.00001, risk=8.0, bucket="os_execution") == snapshot.rarity_high_risk_multiplier
    assert rarity_multiplier_for_probability(0.5, risk=0.0, bucket="other_behavior") == snapshot.rarity_default_multiplier


def test_apply_ecosystem_gate_rejects_hostile_gate_inputs_without_hooks():
    _reset_hostile_state()
    tags = []

    suspicious, limit = apply_ecosystem_gate(ArchiveEcosystemGateRequest(
        tags,
        False,
        HostileNumber(),
        HostileNumber(),
        HostileNumber(),
        path=HostileText(),
    ))

    _assert_no_hostile_hooks()
    assert suspicious is True
    assert limit == 1
    assert "archive_ecosystem_gate_input_unsafe" in tags
    assert "archive_ecosystem_boundary:archive_ecosystem_gate_input_unsafe" in tags
    assert "archive_ecosystem_boundary_path" not in tags
    assert "archive_final_json_must_record" in tags


def test_apply_ecosystem_gate_preserves_exact_primitive_behavior():
    tags = []

    suspicious, limit = apply_ecosystem_gate(ArchiveEcosystemGateRequest(tags, False, 9999.0, 100, 50, path="archive.zip"))

    assert suspicious is True
    assert limit == 25
    assert "archive_ecosystem_score_limit" in tags
    assert "archive_ecosystem_member_scan_limited" in tags
    assert "archive_ecosystem_boundary_path" in tags
