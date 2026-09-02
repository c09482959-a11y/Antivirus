"""Stage1598: scanner binary numeric clamp rejects hookable numeric objects."""
from __future__ import annotations

import math

import pytest

from Virus_Scan.scanners.binary_numeric import safe_clamp


class HostileFloat:
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __float__")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __int__")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __repr__")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __str__")


class IntSubclass(int):
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not call subclass __float__")


@pytest.mark.parametrize(
    "args",
    [
        (HostileFloat(),),
        (0.25, HostileFloat(), 1.0),
        (0.25, 0.0, HostileFloat()),
        (IntSubclass(1),),
        (True,),
    ],
)
def test_stage1598_binary_safe_clamp_rejects_hookable_numeric_objects_without_hooks(args):
    HostileFloat.touched = 0
    IntSubclass.touched = 0

    with pytest.raises(TypeError):
        safe_clamp(*args)

    assert HostileFloat.touched == 0
    assert IntSubclass.touched == 0


def test_stage1598_binary_safe_clamp_preserves_exact_primitive_numeric_behavior():
    assert safe_clamp(-5) == 0.0
    assert safe_clamp(5) == 1.0
    assert safe_clamp(0.25) == 0.25
    assert safe_clamp(math.nan) == 0.0
    assert safe_clamp(math.inf, 0.15, 0.85) == 0.15
    assert safe_clamp(0.5, 1.0, 0.0) == 0.5
