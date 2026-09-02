from Virus_Scan.detection.evidence.relationships.stage_collector_merge import merge_stage_collector_results


class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")


class HostileBool:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")


class HostileRecord:
    touched = 0

    def get(self, *args, **kwargs):
        type(self).touched += 1
        raise RuntimeError("do not call get")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not call items")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")


class HostileMapping(dict):
    touched = 0

    def get(self, *args, **kwargs):
        type(self).touched += 1
        raise RuntimeError("do not call get")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not call items")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call repr")


def _reset():
    HostileText.touched = 0
    HostileBool.touched = 0
    HostileRecord.touched = 0
    HostileMapping.touched = 0


def test_stage1683_merge_rejects_hostile_record_without_mapping_or_text_hooks():
    _reset()

    merged = merge_stage_collector_results([HostileRecord(), HostileMapping({"name": "hidden"})])
    tags, _metadata, suspicious, errors = merged.as_tuple()

    assert suspicious is False
    assert "stage_collector_record_unavailable" in tags
    assert any(isinstance(error, dict) and error.get("source_unavailable_reason") == "stage_collector_record_unavailable" for error in errors)
    assert HostileRecord.touched == 0
    assert HostileMapping.touched == 0


def test_stage1683_merge_rejects_hostile_fields_without_bool_str_or_repr_hooks():
    _reset()

    merged = merge_stage_collector_results([
        {
            "name": HostileText(),
            "tags": ("safe_tag", HostileText()),
            "meta": HostileMapping({"hidden": "value"}),
            "suspicious": HostileBool(),
            "error": HostileText(),
        }
    ])
    tags, metadata, suspicious, errors = merged.as_tuple()

    assert suspicious is False
    assert "safe_tag" in tags
    assert "stage_stage_error" in tags
    assert "stage" in metadata
    assert any(isinstance(error, dict) and error.get("source_unavailable_reason") == "stage_collector_name_unavailable" for error in errors)
    assert any(isinstance(error, dict) and error.get("source_unavailable_reason") == "stage_collector_meta_unavailable" for error in errors)
    assert any(isinstance(error, dict) and error.get("source_unavailable_reason") == "stage_collector_suspicious_unavailable" for error in errors)
    assert any(isinstance(error, dict) and error.get("source_unavailable_reason") == "stage_collector_error_unavailable" for error in errors)
    assert HostileText.touched == 0
    assert HostileBool.touched == 0
    assert HostileMapping.touched == 0


def test_stage1683_merge_preserves_exact_builtin_stage_output_behavior():
    merged = merge_stage_collector_results([
        {
            "name": "static",
            "tags": ["tag_a", "tag_a", "tag_b"],
            "meta": {"count": 2},
            "suspicious": True,
            "error": "failed",
        }
    ])
    tags, metadata, suspicious, errors = merged.as_tuple()

    assert suspicious is True
    assert tags == ["tag_a", "tag_b", "static_stage_error"]
    assert metadata == {"static": {"count": 2}}
    assert "static:failed" in errors

from Virus_Scan.detection.evidence.relationships.evidence_links import umige_evidence_link_tags


def test_stage1683_evidence_links_reject_hostile_text_without_bool_str_or_repr_hooks():
    _reset()

    tags = umige_evidence_link_tags(HostileText(), path=HostileText())

    assert "detection_stage_degraded" in tags
    assert "decoded_payload_evidence_links_degraded" in tags
    assert "decoded_payload_evidence_links_decoded_payload_evidence_links_text_unavailable" in tags
    assert HostileText.touched == 0


def test_stage1683_evidence_links_preserve_exact_observed_text_behavior():
    tags = umige_evidence_link_tags("base64 http://example.test powershell")

    assert "evidence_link:decode_observed" in tags
    assert "evidence_link:decoded_payload_to_execution" in tags
    assert "evidence_link:decoded_payload_to_network" in tags
    assert "evidence_link:decoded_payload_execution_network_correlation" in tags
