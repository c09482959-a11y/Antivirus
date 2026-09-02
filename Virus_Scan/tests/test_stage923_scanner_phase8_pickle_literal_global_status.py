import pytest

from Virus_Scan.scanners.pickle import global_references, literals


class BadString:
    def __str__(self):
        raise TypeError('bad pickle text')


def test_pickle_arg_to_text_uses_status_instead_of_decode_sentinel():
    status, value = literals._pickle_arg_to_text_status(BadString())
    assert status == 'decode_error'
    assert isinstance(value, TypeError)
    with pytest.raises(ValueError):
        literals._pickle_arg_to_text(BadString())


def test_pickle_canonical_global_uses_status_instead_of_parse_sentinel():
    status, value = global_references._pickle_canonical_global_status(BadString())
    assert status == 'parse_error'
    assert isinstance(value, TypeError)
    with pytest.raises(ValueError):
        global_references._pickle_canonical_global(BadString())
