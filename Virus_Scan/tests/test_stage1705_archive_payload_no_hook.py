from Virus_Scan.scanners.archives import payloads


class HostileText:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned text hook executed")

    def __str__(self):
        return self._touch()

    def __repr__(self):
        return self._touch()

    def __format__(self, spec):
        return self._touch()


class HostileContainer:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned container bool executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned container iter executed")


class HostileRecord:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def get(self, _key, _default=None):
        type(self).touched += 1
        raise RuntimeError("caller-owned mapping get executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned mapping bool executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned mapping iter executed")


class HostileRecordSequence:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned record sequence bool executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned record sequence iter executed")


def _call_archive_payload_with(**replacements):
    originals = {name: getattr(payloads, name) for name in replacements}
    for name, value in replacements.items():
        setattr(payloads, name, value)
    try:
        return payloads.archive_member_payload_tags("member.bin", b"payload-bytes", "plain text")
    finally:
        for name, value in originals.items():
            setattr(payloads, name, value)


def _base_replacements(records):
    return {
        "pickle_embedded_payload_tags": lambda _raw, path=None: [],
        "decoded_payload_tags": lambda _text, path=None, finalize=False: [],
        "embedded_payload_records_from_bytes": lambda _raw, encoding_hint="archive_member": records,
    }


def test_stage1705_archive_payload_records_reject_hostile_values_without_hooks():
    HostileText.reset()
    HostileContainer.reset()
    records = [{"text": HostileText(), "binary_magic": HostileText(), "failure_tags": HostileContainer()}]

    tags, suspicious = _call_archive_payload_with(**_base_replacements(records))

    assert suspicious
    assert HostileText.touched == 0
    assert HostileContainer.touched == 0
    assert "payload_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags
    assert "archive_member_payload_failure_evidence_recorded" in tags


def test_stage1705_archive_payload_rejects_hostile_record_object_without_mapping_hooks():
    HostileRecord.reset()

    tags, suspicious = _call_archive_payload_with(**_base_replacements([HostileRecord()]))

    assert suspicious
    assert HostileRecord.touched == 0
    assert "archive_member_payload_record_unsupported" in tags
    assert "archive_final_json_must_record" in tags


def test_stage1705_archive_payload_rejects_hostile_record_sequence_without_iteration():
    HostileRecordSequence.reset()

    tags, suspicious = _call_archive_payload_with(**_base_replacements(HostileRecordSequence()))

    assert suspicious
    assert HostileRecordSequence.touched == 0
    assert "archive_member_payload_record_sequence_unsafe" in tags
    assert "archive_member_payload_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags


def test_stage1705_archive_payload_preserves_exact_binary_magic_behavior():
    records = [{"encoding": "base64", "decode_chain": ("base64",), "text": "MZ", "binary_magic": "pe"}]

    tags, suspicious = _call_archive_payload_with(**_base_replacements(records))

    assert suspicious
    assert "archive_member_embedded_payload_observed" in tags
    assert "payload_decode_candidate" in tags
    assert "decoded_binary_payload" in tags
    assert "decoded_pe_payload" in tags
