from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.runtime.causal_text import causal_scalar_token, causal_sort_key, causal_text



class HostileNameMeta(type):
    touched = 0

    def __getattribute__(cls, name):
        if name == "__name__":
            HostileNameMeta.touched += 1
            raise RuntimeError("metaclass __name__ lookup must not execute")
        return type.__getattribute__(cls, name)


class HostileMetaclassValue(metaclass=HostileNameMeta):
    def __str__(self):
        HostileNameMeta.touched += 100
        raise RuntimeError("caller-owned __str__ must not execute")

    def __repr__(self):
        HostileNameMeta.touched += 100
        raise RuntimeError("caller-owned __repr__ must not execute")

    def __format__(self, _spec):
        HostileNameMeta.touched += 100
        raise RuntimeError("caller-owned __format__ must not execute")


def test_stage1757_causal_text_type_name_rejects_hostile_metaclass_without_hooks() -> None:
    HostileNameMeta.touched = 0
    value = HostileMetaclassValue()

    text = causal_text(value)
    sort_key = causal_sort_key(value)
    scalar = causal_scalar_token(value)

    assert HostileNameMeta.touched == 0
    assert text == "causal_text_unavailable:HostileMetaclassValue"
    assert sort_key == ("causal_text_unavailable:HostileMetaclassValue", "HostileMetaclassValue")
    assert scalar == "<HostileMetaclassValue>"


def test_stage1757_causal_text_source_uses_no_hook_type_name_not_getattr() -> None:
    source = read_python_file(Path("Virus_Scan/runtime/causal_text.py"))

    assert "getattr(" not in source
    assert "no_hook_type_name" in source
