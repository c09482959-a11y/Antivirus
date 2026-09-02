from collections import Counter, defaultdict
from types import MappingProxyType

import pytest

from Virus_Scan.runtime.init_state import freeze_init_value


def test_freeze_init_value_preserves_counter_as_immutable_numeric_snapshot():
    source = Counter({'z': 2, 'a': 3})
    frozen = freeze_init_value(source)

    assert isinstance(frozen, MappingProxyType)
    assert dict(frozen) == {'a': 3, 'z': 2}
    source['a'] = 99
    assert dict(frozen) == {'a': 3, 'z': 2}
    with pytest.raises(TypeError):
        frozen['a'] = 1


def test_freeze_init_value_strips_defaultdict_factory_and_freezes_nested_values():
    source = defaultdict(list)
    source['b'].append({'nested': ['x']})
    source['a'].append('first')

    frozen = freeze_init_value(source)

    assert isinstance(frozen, MappingProxyType)
    assert tuple(frozen.keys()) == ('a', 'b')
    assert frozen['a'] == ('first',)
    assert isinstance(frozen['b'][0], MappingProxyType)
    assert frozen['b'][0]['nested'] == ('x',)
    source['b'][0]['nested'].append('changed')
    assert frozen['b'][0]['nested'] == ('x',)
