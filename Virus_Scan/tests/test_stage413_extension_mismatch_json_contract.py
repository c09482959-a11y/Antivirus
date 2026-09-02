from Virus_Scan.publication.json_writer import compact_result_record


def test_extension_mismatch_tag_sets_boolean_and_engine_context():
    record = compact_result_record(
        {
            "path": "sample.dat",
            "score": 25,
            "classification": "medium",
            "declared_extension": ".dat",
            "sniffed_type": "pe",
            "tags": ["extension_magic_type_mismatch", "pe_file"],
        }
    )

    assert record["extension_mismatch"] is True
    assert record["engine_context"]["extension_mismatch"] is True
    assert "extension_magic_type_mismatch" in record["tags"]


def test_declared_sniffed_tag_sets_extension_mismatch_boolean():
    record = compact_result_record(
        {
            "path": "sample.png",
            "score": 25,
            "classification": "medium",
            "declared_extension": ".png",
            "sniffed_type": "pe",
            "tags": ["declared_png_sniffs_as_pe"],
        }
    )

    assert record["extension_mismatch"] is True
    assert record["engine_context"]["extension_mismatch"] is True
