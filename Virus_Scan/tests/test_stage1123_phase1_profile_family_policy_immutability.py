import pytest

from Virus_Scan.detection.profiles import family_scan


def test_stage1123_family_scan_media_extension_policy_is_immutable():
    assert isinstance(family_scan.MEDIA_EXTENSIONS, frozenset)
    assert '.png' in family_scan.MEDIA_EXTENSIONS
    with pytest.raises(AttributeError):
        family_scan.MEDIA_EXTENSIONS.add('.exe')


def test_stage1123_family_scan_media_stego_behavior_preserved_for_known_media():
    tags = family_scan.explicit_missed_family_tag_scan(
        'payload after iend with hidden payload',
        path='image.png',
        data=b'\x89PNG' + b'a' * 2048 + b'MZ',
    )
    assert 'possible_stego_payload' in tags
    assert 'image_payload_candidate' in tags
